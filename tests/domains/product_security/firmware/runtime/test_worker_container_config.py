from __future__ import annotations

import json
import re
from pathlib import Path


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
