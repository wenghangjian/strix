from __future__ import annotations

from strix.domains.product_security.firmware.runtime.docker_attach import (
    SocketDockerAttachSession,
)
from strix.domains.product_security.firmware.runtime.worker_container import (
    ContainerObservation,
    FirmwareWorkerContainer,
)


class FakeRawSocket:
    def __init__(self) -> None:
        self.sent = bytearray()
        self.closed = False

    def send(self, data: bytes | memoryview) -> int:
        self.sent.extend(data)
        return len(data)

    def recv(self, _maximum: int) -> bytes:
        return b""

    def shutdown(self, _how: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeAttachOwner:
    def __init__(self) -> None:
        self._sock = FakeRawSocket()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class LifecycleDockerAPI:
    def __init__(self, *, running: bool = True) -> None:
        self.calls: list[tuple[str, object]] = []
        self.running = running
        self.owner = FakeAttachOwner()

    def create_host_config(self, **_kwargs: object) -> dict[str, object]:
        return {}

    def create_container_config(self, **_kwargs: object) -> dict[str, object]:
        return {}

    def create_container_from_config(
        self,
        _config: dict[str, object],
        name: str | None = None,
        platform: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("create", (name, platform)))
        return {"Id": "container-123"}

    def start(self, container: str) -> None:
        self.calls.append(("start", container))

    def attach_socket(
        self,
        container: str,
        params: dict[str, int] | None = None,
        ws: bool = False,
    ) -> FakeAttachOwner:
        self.calls.append(("attach", (container, params, ws)))
        return self.owner

    def inspect_container(self, container: str) -> dict[str, object]:
        self.calls.append(("inspect", container))
        return {
            "Id": container,
            "State": {
                "Status": "running" if self.running else "exited",
                "Running": self.running,
                "ExitCode": 0,
                "OOMKilled": False,
                "Error": "",
            },
        }

    def kill(self, container: str) -> None:
        self.calls.append(("kill", container))
        self.running = False

    def wait(
        self,
        container: str,
        timeout: int | None = None,
        condition: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("wait", (container, timeout, condition)))
        return {"StatusCode": 137}

    def remove_container(
        self,
        container: str,
        v: bool = False,
        link: bool = False,
        force: bool = False,
    ) -> None:
        self.calls.append(("remove", (container, v, link, force)))


def _container(api: LifecycleDockerAPI) -> FirmwareWorkerContainer:
    return FirmwareWorkerContainer(
        api,
        scan_id="scan-trusted-123",
        analysis_id="fw_analysis_aaaaaaaaaaaaaaaa",
    )


def test_start_and_attach_uses_only_stdin_stdout_raw_stream() -> None:
    api = LifecycleDockerAPI()
    container = _container(api)
    container.create()

    session = container.start_and_attach()
    session.write_all(b"FWAP")

    assert isinstance(session, SocketDockerAttachSession)
    assert api.calls[:3] == [
        ("create", ("strix-firmware-aaaaaaaaaaaaaaaa", "linux/amd64")),
        ("start", "container-123"),
        (
            "attach",
            (
                "container-123",
                {"stdin": 1, "stdout": 1, "stderr": 0, "stream": 1},
                False,
            ),
        ),
    ]
    assert api.owner._sock.sent == b"FWAP"


def test_destroy_closes_inspects_kills_waits_and_force_removes() -> None:
    api = LifecycleDockerAPI(running=True)
    container = _container(api)
    container.create()
    container.start_and_attach()
    api.calls.clear()

    observation = container.destroy()

    assert api.owner.closed
    assert api.owner._sock.closed
    assert api.calls == [
        ("inspect", "container-123"),
        ("kill", "container-123"),
        ("wait", ("container-123", 5, "not-running")),
        ("remove", ("container-123", False, False, True)),
    ]
    assert observation == ContainerObservation(
        container_id="container-123",
        status="running",
        running=True,
        exit_code=137,
        oom_killed=False,
        error=None,
        removed=True,
        cleanup_errors=(),
    )


def test_destroy_is_idempotent_and_skips_kill_for_exited_container() -> None:
    api = LifecycleDockerAPI(running=False)
    container = _container(api)
    container.create()
    api.calls.clear()

    first = container.destroy()
    call_count = len(api.calls)
    second = container.destroy()

    assert first is second
    assert len(api.calls) == call_count
    assert [name for name, _ in api.calls] == ["inspect", "wait", "remove"]


def test_inspect_returns_typed_observation() -> None:
    api = LifecycleDockerAPI(running=False)
    container = _container(api)
    container.create()

    assert container.inspect() == ContainerObservation(
        container_id="container-123",
        status="exited",
        running=False,
        exit_code=0,
        oom_killed=False,
        error=None,
        removed=False,
        cleanup_errors=(),
    )
