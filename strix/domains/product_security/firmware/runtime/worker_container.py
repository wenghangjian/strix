"""Restricted one-shot Docker lifecycle for the P2a firmware worker."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from docker.types import LogConfig
from requests.exceptions import RequestException

from docker import errors as docker_errors  # type: ignore[attr-defined]
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.runtime.docker_attach import (
    DockerAttachSession,
    SocketDockerAttachSession,
)


MEMORY_BYTES = 4_294_967_296
NANO_CPUS = 2_000_000_000
PIDS_LIMIT = 64
WORK_TMPFS = "rw,noexec,nosuid,nodev,size=2147483648,mode=0700"
CONTAINER_WAIT_SECONDS = 5

_ANALYSIS_ID = re.compile(r"^fw_analysis_[0-9a-f]{16,64}$")
_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_WORKER_IMAGE_DIR = _REPOSITORY_ROOT / "docker" / "firmware-worker"


class _SocketTransport(Protocol):
    def send(self, data: bytes | memoryview) -> int: ...

    def recv(self, maximum: int) -> bytes: ...

    def shutdown(self, how: int) -> None: ...

    def close(self) -> None: ...


class _Closeable(Protocol):
    def close(self) -> None: ...


class _DockerAPI(Protocol):
    def create_host_config(self, **kwargs: object) -> dict[str, object]: ...

    def create_container_config(self, **kwargs: object) -> dict[str, object]: ...

    def create_container_from_config(
        self,
        config: dict[str, object],
        name: str | None = None,
        platform: str | None = None,
    ) -> dict[str, object]: ...

    def start(self, container: str) -> None: ...

    def attach_socket(
        self,
        container: str,
        params: dict[str, int] | None = None,
        ws: bool = False,
    ) -> object: ...

    def inspect_container(self, container: str) -> dict[str, object]: ...

    def kill(self, container: str) -> None: ...

    def wait(
        self,
        container: str,
        timeout: int | None = None,
        condition: str | None = None,
    ) -> dict[str, object]: ...

    def remove_container(
        self,
        container: str,
        v: bool = False,
        link: bool = False,
        force: bool = False,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class FirmwareWorkerContainerSpec:
    scan_id: str
    analysis_id: str

    def __post_init__(self) -> None:
        if _SCAN_ID.fullmatch(self.scan_id) is None:
            raise ValueError("scan_id is not safe for a trusted Docker label")
        if _ANALYSIS_ID.fullmatch(self.analysis_id) is None:
            raise ValueError("analysis_id does not match the firmware identity contract")

    @property
    def container_name(self) -> str:
        return f"strix-firmware-{self.analysis_id.removeprefix('fw_analysis_')}"


@dataclass(frozen=True, slots=True)
class ContainerObservation:
    container_id: str | None
    status: str | None
    running: bool
    exit_code: int | None
    oom_killed: bool
    error: str | None
    removed: bool
    cleanup_errors: tuple[str, ...]


class _AttachedSocketAdapter:
    def __init__(self, owner: object) -> None:
        self._owner = cast("_Closeable", owner)
        underlying = getattr(owner, "_sock", owner)
        self._transport = cast("_SocketTransport", underlying)
        self._same_object = underlying is owner
        self._closed = False

    def send(self, data: bytes | memoryview) -> int:
        return self._transport.send(data)

    def recv(self, maximum: int) -> bytes:
        return self._transport.recv(maximum)

    def shutdown(self, how: int) -> None:
        self._transport.shutdown(how)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._owner.close()
        finally:
            if not self._same_object:
                self._transport.close()


class FirmwareWorkerContainer:
    def __init__(
        self,
        docker_api: object,
        *,
        scan_id: str,
        analysis_id: str,
    ) -> None:
        self.spec = FirmwareWorkerContainerSpec(scan_id=scan_id, analysis_id=analysis_id)
        self._api = cast("_DockerAPI", docker_api)
        self._image_digest = _read_worker_image_digest()
        self._seccomp_profile = _read_seccomp_profile()
        self._container_id: str | None = None
        self._attach_session: SocketDockerAttachSession | None = None
        self._destroyed_observation: ContainerObservation | None = None

    @property
    def container_id(self) -> str | None:
        return self._container_id

    def create(self) -> None:
        if self._container_id is not None:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_CONTAINER_ALREADY_CREATED",
                "Firmware worker container has already been created.",
                retryable=False,
            )
        try:
            host_config = self._api.create_host_config(**self._host_config())
            container_config = self._api.create_container_config(
                image=self._image_digest,
                command=None,
                hostname=None,
                user="65532:65532",
                detach=False,
                stdin_open=True,
                tty=False,
                ports=[],
                environment=_worker_environment(),
                volumes=[],
                network_disabled=True,
                entrypoint=None,
                working_dir="/work",
                domainname=None,
                host_config=host_config,
                mac_address=None,
                labels=self._labels(),
                stop_signal="SIGTERM",
                networking_config=None,
                healthcheck={"Test": ["NONE"]},
                stop_timeout=CONTAINER_WAIT_SECONDS,
                runtime=None,
            )
            container_config.update(
                {
                    "AttachStdin": True,
                    "AttachStdout": True,
                    "AttachStderr": False,
                    "OpenStdin": True,
                    "StdinOnce": False,
                    "Tty": False,
                }
            )
            created = self._api.create_container_from_config(
                container_config,
                name=self.spec.container_name,
                platform="linux/amd64",
            )
        except (
            docker_errors.DockerException,
            RequestException,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_CONTAINER_CREATE_FAILED",
                "Firmware worker container creation failed.",
                retryable=False,
            ) from exc
        self._container_id = _created_container_id(created)

    def start_and_attach(self) -> DockerAttachSession:
        container_id = self._require_container_id()
        if self._attach_session is not None:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_ALREADY_ATTACHED",
                "Firmware worker container is already attached.",
                retryable=False,
            )
        try:
            self._api.start(container_id)
            owner = self._api.attach_socket(
                container_id,
                params={"stdin": 1, "stdout": 1, "stderr": 0, "stream": 1},
                ws=False,
            )
            session = SocketDockerAttachSession(_AttachedSocketAdapter(owner))
        except (docker_errors.DockerException, RequestException, OSError, TypeError) as exc:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_ATTACH_FAILED",
                "Firmware worker container start or attach failed.",
                retryable=False,
            ) from exc
        self._attach_session = session
        return session

    def inspect(self) -> ContainerObservation:
        if self._destroyed_observation is not None:
            return self._destroyed_observation
        container_id = self._require_container_id()
        try:
            return _observation_from_inspect(
                container_id,
                self._api.inspect_container(container_id),
            )
        except (
            docker_errors.DockerException,
            RequestException,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_INSPECT_FAILED",
                "Firmware worker container inspection failed.",
                retryable=False,
            ) from exc

    def destroy(self) -> ContainerObservation:
        if self._destroyed_observation is not None:
            return self._destroyed_observation
        if self._container_id is None:
            observation = ContainerObservation(
                container_id=None,
                status="not_created",
                running=False,
                exit_code=None,
                oom_killed=False,
                error=None,
                removed=True,
                cleanup_errors=(),
            )
            self._destroyed_observation = observation
            return observation

        container_id = self._container_id
        cleanup_errors: list[str] = []
        self._close_attach(cleanup_errors)
        observation = self._inspect_for_cleanup(container_id, cleanup_errors)

        if observation.running:
            try:
                self._api.kill(container_id)
            except docker_errors.NotFound:
                pass
            except (docker_errors.DockerException, RequestException, OSError):
                cleanup_errors.append("kill_failed")

        exit_code = observation.exit_code
        try:
            waited = self._api.wait(
                container_id,
                timeout=CONTAINER_WAIT_SECONDS,
                condition="not-running",
            )
            waited_code = waited.get("StatusCode")
            if isinstance(waited_code, int) and not isinstance(waited_code, bool):
                exit_code = waited_code
        except docker_errors.NotFound:
            pass
        except (docker_errors.DockerException, RequestException, OSError):
            cleanup_errors.append("wait_failed")

        removed = False
        try:
            self._api.remove_container(container_id, v=False, link=False, force=True)
            removed = True
        except docker_errors.NotFound:
            removed = True
        except (docker_errors.DockerException, RequestException, OSError):
            cleanup_errors.append("remove_failed")

        final = ContainerObservation(
            container_id=container_id,
            status=observation.status,
            running=observation.running,
            exit_code=exit_code,
            oom_killed=observation.oom_killed,
            error=observation.error,
            removed=removed,
            cleanup_errors=tuple(cleanup_errors),
        )
        if removed:
            self._destroyed_observation = final
        return final

    def _host_config(self) -> dict[str, object]:
        return {
            "auto_remove": False,
            "binds": {},
            "cap_add": [],
            "cap_drop": ["ALL"],
            "cgroupns": "private",
            "device_cgroup_rules": [],
            "device_requests": [],
            "devices": [],
            "group_add": [],
            "ipc_mode": "private",
            "links": {},
            "log_config": LogConfig(type=LogConfig.types.NONE),
            "mem_limit": MEMORY_BYTES,
            "memswap_limit": MEMORY_BYTES,
            "mounts": [],
            "nano_cpus": NANO_CPUS,
            "network_mode": "none",
            "oom_kill_disable": False,
            "pids_limit": PIDS_LIMIT,
            "port_bindings": {},
            "privileged": False,
            "publish_all_ports": False,
            "read_only": True,
            "restart_policy": {"Name": "no", "MaximumRetryCount": 0},
            "security_opt": [
                "no-new-privileges:true",
                f"seccomp={self._seccomp_profile}",
                "apparmor=docker-default",
            ],
            "tmpfs": {"/work": WORK_TMPFS},
            "volumes_from": [],
        }

    def _labels(self) -> dict[str, str]:
        return {
            "io.strix.firmware.worker": "p2a",
            "io.strix.firmware.scan-id": self.spec.scan_id,
            "io.strix.firmware.analysis-id": self.spec.analysis_id,
        }

    def _require_container_id(self) -> str:
        if self._container_id is None:
            raise FirmwareDomainError(
                "FIRMWARE_WORKER_CONTAINER_NOT_CREATED",
                "Firmware worker container has not been created.",
                retryable=False,
            )
        return self._container_id

    def _close_attach(self, cleanup_errors: list[str]) -> None:
        if self._attach_session is None:
            return
        try:
            self._attach_session.close()
        except (FWAPProtocolError, OSError):
            cleanup_errors.append("attach_close_failed")
        finally:
            self._attach_session = None

    def _inspect_for_cleanup(
        self,
        container_id: str,
        cleanup_errors: list[str],
    ) -> ContainerObservation:
        try:
            return _observation_from_inspect(
                container_id,
                self._api.inspect_container(container_id),
            )
        except docker_errors.NotFound:
            return _unknown_observation(container_id)
        except (
            docker_errors.DockerException,
            RequestException,
            OSError,
            TypeError,
            ValueError,
        ):
            cleanup_errors.append("inspect_failed")
            return _unknown_observation(container_id)


def _worker_environment() -> dict[str, str]:
    return {
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _created_container_id(created: dict[str, object]) -> str:
    container_id = created.get("Id")
    if not isinstance(container_id, str) or not container_id:
        raise FirmwareDomainError(
            "FIRMWARE_WORKER_CONTAINER_CREATE_FAILED",
            "Firmware worker container creation returned no container ID.",
            retryable=False,
        )
    return container_id


def _read_worker_image_digest() -> str:
    entries: dict[str, str] = {}
    try:
        for line in (_WORKER_IMAGE_DIR / "worker-image.lock").read_text(
            encoding="utf-8"
        ).splitlines():
            key, value = line.split("=", maxsplit=1)
            entries[key] = value
    except (OSError, ValueError) as exc:
        raise FirmwareDomainError(
            "FIRMWARE_WORKER_IMAGE_LOCK_INVALID",
            "Firmware worker image lock is missing or invalid.",
            retryable=False,
        ) from exc
    image_digest = entries.get("image_digest", "")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise FirmwareDomainError(
            "FIRMWARE_WORKER_IMAGE_LOCK_INVALID",
            "Firmware worker image lock has an invalid image digest.",
            retryable=False,
        )
    return image_digest


def _read_seccomp_profile() -> str:
    try:
        decoded: object = json.loads(
            (_WORKER_IMAGE_DIR / "seccomp.json").read_bytes()
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise FirmwareDomainError(
            "FIRMWARE_WORKER_SECCOMP_INVALID",
            "Firmware worker seccomp profile is missing or invalid.",
            retryable=False,
        ) from exc
    if not isinstance(decoded, dict):
        raise FirmwareDomainError(
            "FIRMWARE_WORKER_SECCOMP_INVALID",
            "Firmware worker seccomp profile must be a JSON object.",
            retryable=False,
        )
    return json.dumps(decoded, sort_keys=True, separators=(",", ":"))


def _observation_from_inspect(
    container_id: str,
    inspected: dict[str, object],
) -> ContainerObservation:
    state_value = inspected.get("State")
    if not isinstance(state_value, dict):
        raise TypeError("Docker inspection omitted State")
    state = cast("dict[str, object]", state_value)
    running = state.get("Running")
    if not isinstance(running, bool):
        raise TypeError("Docker inspection has invalid Running state")
    status_value = state.get("Status")
    status = status_value if isinstance(status_value, str) else None
    exit_value = state.get("ExitCode")
    exit_code = (
        exit_value
        if isinstance(exit_value, int) and not isinstance(exit_value, bool)
        else None
    )
    oom_value = state.get("OOMKilled")
    oom_killed = oom_value if isinstance(oom_value, bool) else False
    error_value = state.get("Error")
    error = error_value if isinstance(error_value, str) and error_value else None
    return ContainerObservation(
        container_id=container_id,
        status=status,
        running=running,
        exit_code=exit_code,
        oom_killed=oom_killed,
        error=error,
        removed=False,
        cleanup_errors=(),
    )


def _unknown_observation(container_id: str) -> ContainerObservation:
    return ContainerObservation(
        container_id=container_id,
        status=None,
        running=False,
        exit_code=None,
        oom_killed=False,
        error=None,
        removed=False,
        cleanup_errors=(),
    )
