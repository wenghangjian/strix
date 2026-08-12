#!/usr/bin/env python3
"""Build-lock and runtime verification for the restricted firmware image."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


IMAGE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = IMAGE_DIR.parents[1]
LOCK_PATH = IMAGE_DIR / "worker-image.lock"
EXPECTED_ENTRYPOINT = [
    "/usr/local/bin/python3.12",
    "-m",
    "strix.domains.product_security.firmware.worker",
]
EXPECTED_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "PYTHONPATH": "/app:/opt/firmware-worker/site-packages",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def worker_source_digest() -> str:
    relative_paths = [
        Path("docker/firmware-worker/Dockerfile"),
        Path("docker/firmware-worker/seccomp.json"),
        Path("strix/domains/product_security/firmware/errors.py"),
    ]
    relative_paths.extend(
        path.relative_to(REPOSITORY_ROOT)
        for path in sorted(
            (REPOSITORY_ROOT / "strix/domains/product_security/firmware/protocol").glob("**/*.py")
        )
    )
    worker_dir = REPOSITORY_ROOT / "strix/domains/product_security/firmware/worker"
    if worker_dir.is_dir():
        relative_paths.extend(
            path.relative_to(REPOSITORY_ROOT) for path in sorted(worker_dir.glob("**/*.py"))
        )

    digest = hashlib.sha256()
    for relative_path in sorted(relative_paths):
        digest.update(relative_path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update((REPOSITORY_ROOT / relative_path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _read_lock() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in LOCK_PATH.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", maxsplit=1)
        entries[key] = value
    return entries


def _docker_json(arguments: list[str]) -> Any:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker executable is unavailable")
    completed = subprocess.run(  # noqa: S603
        [docker, *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _docker_run(arguments: list[str]) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker executable is unavailable")
    subprocess.run([docker, *arguments], check=True)  # noqa: S603


def verify_image(image: str) -> None:
    lock = _read_lock()
    inspected = _docker_json(["image", "inspect", image])[0]
    config = inspected["Config"]
    labels = config["Labels"]
    environment = dict(item.split("=", maxsplit=1) for item in config["Env"])

    assert inspected["Id"] == lock["image_digest"]
    assert config["User"] == "65532:65532"
    assert config["Entrypoint"] == EXPECTED_ENTRYPOINT
    assert labels["io.strix.firmware.worker.source-digest"] == lock["worker_source_digest"]
    assert lock["worker_source_digest"] == worker_source_digest()
    assert environment["STRIX_FIRMWARE_WORKER_BUILD_ID"] == lock["worker_source_digest"]
    for key, value in EXPECTED_ENVIRONMENT.items():
        assert environment[key] == value
    assert not any(key.lower().endswith("proxy") for key in environment)

    runtime_check = """
import bz2
import hashlib
import lzma
import os
import socket
import sys
import zlib
import pydantic
from strix.domains.product_security.firmware.protocol.constants import PROTOCOL_MAJOR
from strix.domains.product_security.firmware.worker.session import WorkerSession

assert sys.version_info[:2] == (3, 12)
assert (os.getuid(), os.getgid()) == (65532, 65532)
assert PROTOCOL_MAJOR == 1
assert WorkerSession.__name__ == "WorkerSession"
assert zlib.decompress(zlib.compress(b"firmware")) == b"firmware"
assert bz2.decompress(bz2.compress(b"firmware")) == b"firmware"
assert lzma.decompress(lzma.compress(b"firmware")) == b"firmware"
assert hashlib.sha256(b"firmware").hexdigest().startswith("c3bf")
try:
    socket.socket()
except PermissionError:
    pass
else:
    raise AssertionError("seccomp allowed socket creation")
for forbidden in (
    "/bin/sh",
    "/bin/bash",
    "/busybox/sh",
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/local/bin/pip",
    "/usr/local/bin/pip3",
    "/usr/local/lib/python3.12/ensurepip",
):
    assert not os.path.exists(forbidden), forbidden
"""
    _docker_run(
        [
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--user=65532:65532",
            f"--security-opt=seccomp={IMAGE_DIR / 'seccomp.json'}",
            "--entrypoint=/usr/local/bin/python3.12",
            image,
            "-c",
            runtime_check,
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    parser.add_argument("--print-source-digest", action="store_true")
    arguments = parser.parse_args()
    if arguments.print_source_digest:
        sys.stdout.write(f"{worker_source_digest()}\n")
        return
    if arguments.image is None:
        parser.error("--image is required unless --print-source-digest is used")
    verify_image(arguments.image)


if __name__ == "__main__":
    main()
