from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from docker.types import LogConfig

from strix.domains.product_security.firmware.runtime.worker_container import (
    FirmwareWorkerContainer,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
WORKER_IMAGE_DIR = REPOSITORY_ROOT / "docker" / "firmware-worker"


def _dockerfile() -> str:
    return (WORKER_IMAGE_DIR / "Dockerfile").read_text(encoding="utf-8")


def _lock() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in (WORKER_IMAGE_DIR / "worker-image.lock").read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", maxsplit=1)
        entries[key] = value
    return entries


def test_every_dockerfile_stage_is_digest_pinned() -> None:
    from_lines = [line for line in _dockerfile().splitlines() if line.startswith("FROM ")]

    assert len(from_lines) >= 2
    assert all(re.search(r"@sha256:[0-9a-f]{64}(?:\s+AS\s+\w+)?$", line) for line in from_lines)


def test_final_image_has_fixed_nonroot_identity_and_entrypoint() -> None:
    dockerfile = _dockerfile()

    assert "USER 65532:65532" in dockerfile
    assert (
        'ENTRYPOINT ["/usr/local/bin/python3.12", "-m", '
        '"strix.domains.product_security.firmware.worker"]'
    ) in dockerfile


def test_seccomp_profile_denies_minimum_escape_and_network_syscalls() -> None:
    profile = json.loads((WORKER_IMAGE_DIR / "seccomp.json").read_bytes())
    denied = {
        name
        for rule in profile["syscalls"]
        if rule["action"] in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS"}
        for name in rule["names"]
    }
    required = {
        "mount",
        "umount2",
        "pivot_root",
        "unshare",
        "setns",
        "ptrace",
        "init_module",
        "finit_module",
        "delete_module",
        "mknod",
        "mknodat",
        "socket",
        "socketpair",
        "reboot",
        "kexec_load",
        "iopl",
        "ioperm",
    }

    assert required <= denied
    assert profile["defaultAction"] == "SCMP_ACT_ALLOW"


def test_worker_image_lock_has_complete_digest_bound_identity() -> None:
    lock = _lock()

    assert set(lock) == {
        "image_tag",
        "image_digest",
        "base_image_reference",
        "base_image_digest",
        "worker_source_digest",
        "protocol_version",
        "manifest_schema_version",
        "built_at_utc",
    }
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", lock["image_digest"])
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", lock["base_image_digest"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["worker_source_digest"])
    assert lock["base_image_reference"].endswith(f"@{lock['base_image_digest']}")
    assert lock["protocol_version"] == "1.0"
    assert lock["manifest_schema_version"] == "p2a-manifest-1"


def test_build_and_verification_scripts_enforce_identity() -> None:
    build_script = (WORKER_IMAGE_DIR / "build-image.sh").read_text(encoding="utf-8")
    verify_script = (WORKER_IMAGE_DIR / "verify-image.py").read_text(encoding="utf-8")

    assert "worker_source_digest" in build_script
    assert "docker build" in build_script
    assert "docker image inspect" in build_script
    assert "65532:65532" in verify_script
    assert "/bin/sh" in verify_script
    assert "/usr/local/bin/pip" in verify_script


class RecordingDockerAPI:
    def __init__(self) -> None:
        self.host_config_kwargs: dict[str, object] | None = None
        self.container_config_kwargs: dict[str, object] | None = None
        self.created_config: dict[str, object] | None = None
        self.created_name: str | None = None

    def create_host_config(self, **kwargs: object) -> dict[str, object]:
        self.host_config_kwargs = kwargs
        return {"host-config": True}

    def create_container_config(self, **kwargs: object) -> dict[str, object]:
        self.container_config_kwargs = kwargs
        return {
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": True,
            "OpenStdin": False,
            "StdinOnce": True,
            "Tty": True,
        }

    def create_container_from_config(
        self,
        config: dict[str, object],
        name: str | None = None,
        platform: str | None = None,
    ) -> dict[str, object]:
        assert platform == "linux/amd64"
        self.created_config = config
        self.created_name = name
        return {"Id": "container-123"}


def _container(api: RecordingDockerAPI) -> FirmwareWorkerContainer:
    return FirmwareWorkerContainer(
        api,
        scan_id="scan-trusted-123",
        analysis_id="fw_analysis_aaaaaaaaaaaaaaaa",
    )


def test_container_uses_exact_restricted_host_config() -> None:
    api = RecordingDockerAPI()
    seccomp = json.dumps(
        json.loads((WORKER_IMAGE_DIR / "seccomp.json").read_bytes()),
        sort_keys=True,
        separators=(",", ":"),
    )

    _container(api).create()

    assert api.host_config_kwargs == {
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
        "mem_limit": 4_294_967_296,
        "memswap_limit": 4_294_967_296,
        "mounts": [],
        "nano_cpus": 2_000_000_000,
        "network_mode": "none",
        "oom_kill_disable": False,
        "pids_limit": 64,
        "port_bindings": {},
        "privileged": False,
        "publish_all_ports": False,
        "read_only": True,
        "restart_policy": {"Name": "no", "MaximumRetryCount": 0},
        "security_opt": [
            "no-new-privileges:true",
            f"seccomp={seccomp}",
            "apparmor=docker-default",
        ],
        "tmpfs": {
            "/work": "rw,noexec,nosuid,nodev,size=2147483648,mode=0700",
        },
        "volumes_from": [],
    }


def test_container_config_has_only_fixed_attach_identity_and_environment() -> None:
    api = RecordingDockerAPI()

    container = _container(api)
    container.create()

    lock = _lock()
    assert api.container_config_kwargs == {
        "image": lock["image_digest"],
        "command": None,
        "hostname": None,
        "user": "65532:65532",
        "detach": False,
        "stdin_open": True,
        "tty": False,
        "ports": [],
        "environment": {
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        "volumes": [],
        "network_disabled": True,
        "entrypoint": None,
        "working_dir": "/work",
        "domainname": None,
        "host_config": {"host-config": True},
        "mac_address": None,
        "labels": {
            "io.strix.firmware.worker": "p2a",
            "io.strix.firmware.scan-id": "scan-trusted-123",
            "io.strix.firmware.analysis-id": "fw_analysis_aaaaaaaaaaaaaaaa",
        },
        "stop_signal": "SIGTERM",
        "networking_config": None,
        "healthcheck": {"Test": ["NONE"]},
        "stop_timeout": 5,
        "runtime": None,
    }
    assert api.created_config == {
        "AttachStdin": True,
        "AttachStdout": True,
        "AttachStderr": False,
        "OpenStdin": True,
        "StdinOnce": False,
        "Tty": False,
    }
    assert api.created_name == "strix-firmware-aaaaaaaaaaaaaaaa"
    assert container.container_id == "container-123"


def test_container_spec_is_frozen_and_rejects_untrusted_identifiers() -> None:
    api = RecordingDockerAPI()
    container = _container(api)

    with pytest.raises((AttributeError, TypeError)):
        container.spec.scan_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="analysis_id"):
        FirmwareWorkerContainer(api, scan_id="scan", analysis_id="not-trusted")
    with pytest.raises(ValueError, match="scan_id"):
        FirmwareWorkerContainer(
            api,
            scan_id="contains\x00nul",
            analysis_id="fw_analysis_aaaaaaaaaaaaaaaa",
        )
