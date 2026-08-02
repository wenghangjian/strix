"""Immutable descriptor-based firmware input ingestion."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import FirmwareInputArtifact


if TYPE_CHECKING:
    from strix.domains.product_security.firmware.repository import FirmwareRepository


DEFAULT_MAX_FIRMWARE_INPUT_BYTES = 512 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024


def ingest_firmware_inputs(
    paths: list[str],
    repository: FirmwareRepository,
    *,
    scan_id: str,
    project_id: str | None = None,
    max_input_bytes: int = DEFAULT_MAX_FIRMWARE_INPUT_BYTES,
    source_type: Literal["cli", "upload", "connector", "fixture"] = "cli",
) -> list[FirmwareInputArtifact]:
    """Import configured firmware paths without reopening them after validation."""
    imported: list[FirmwareInputArtifact] = []
    seen_ids: set[str] = set()
    for raw_path in paths:
        source = Path(raw_path).expanduser()
        artifact = _ingest_one(
            source,
            repository,
            scan_id=scan_id,
            project_id=project_id,
            max_input_bytes=max_input_bytes,
            source_type=source_type,
        )
        if artifact.input_artifact_id not in seen_ids:
            imported.append(artifact)
            seen_ids.add(artifact.input_artifact_id)
    return imported


def _ingest_one(
    source: Path,
    repository: FirmwareRepository,
    *,
    scan_id: str,
    project_id: str | None,
    max_input_bytes: int,
    source_type: Literal["cli", "upload", "connector", "fixture"],
) -> FirmwareInputArtifact:
    descriptor = _open_input_descriptor(source)
    staged_path = repository.new_staging_path()
    try:
        return _ingest_descriptor(
            descriptor,
            staged_path,
            source,
            repository,
            scan_id=scan_id,
            project_id=project_id,
            max_input_bytes=max_input_bytes,
            source_type=source_type,
        )
    finally:
        staged_path.unlink(missing_ok=True)
        os.close(descriptor)


def _ingest_descriptor(
    descriptor: int,
    staged_path: Path,
    source: Path,
    repository: FirmwareRepository,
    *,
    scan_id: str,
    project_id: str | None,
    max_input_bytes: int,
    source_type: Literal["cli", "upload", "connector", "fixture"],
) -> FirmwareInputArtifact:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise _invalid_input("Firmware input must be a regular file.")
    if before.st_size <= 0:
        raise _invalid_input("Firmware input must not be empty.")
    if before.st_size > max_input_bytes:
        raise _too_large(max_input_bytes)

    digest, copied_size = _stream_descriptor(
        descriptor,
        staged_path,
        max_input_bytes=max_input_bytes,
    )
    after = os.fstat(descriptor)
    if _descriptor_identity(before) != _descriptor_identity(after):
        raise FirmwareDomainError(
            "FIRMWARE_INPUT_CHANGED",
            "Firmware input changed while it was being imported.",
            retryable=True,
        )
    if copied_size != before.st_size:
        raise FirmwareDomainError(
            "FIRMWARE_INPUT_CHANGED",
            "Firmware input size changed while it was being imported.",
            retryable=True,
        )

    artifact = FirmwareInputArtifact(
        input_artifact_id=f"fw_input_{digest[:16]}",
        scan_id=scan_id,
        project_id=project_id,
        sha256=digest,
        size_bytes=copied_size,
        storage_name=digest,
        label=source.name,
        source_type=source_type,
    )
    return repository.register_input(staged_path, artifact)


def _open_input_descriptor(path: Path) -> int:
    try:
        if path.is_symlink():
            raise _invalid_input("Firmware input symlinks are not allowed.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)
    except FirmwareDomainError:
        raise
    except OSError as exc:
        raise _invalid_input("Firmware input cannot be opened as a regular file.") from exc


def _stream_descriptor(
    descriptor: int,
    staged_path: Path,
    *,
    max_input_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    copied = 0
    with staged_path.open("xb") as destination:
        while chunk := os.read(descriptor, _COPY_CHUNK_BYTES):
            copied += len(chunk)
            if copied > max_input_bytes:
                raise _too_large(max_input_bytes)
            digest.update(chunk)
            destination.write(chunk)
        destination.flush()
        os.fsync(destination.fileno())
    return digest.hexdigest(), copied


def _descriptor_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _invalid_input(message: str) -> FirmwareDomainError:
    return FirmwareDomainError(
        "FIRMWARE_INPUT_INVALID",
        message,
        retryable=False,
    )


def _too_large(max_input_bytes: int) -> FirmwareDomainError:
    return FirmwareDomainError(
        "FIRMWARE_INPUT_TOO_LARGE",
        f"Firmware input exceeds the {max_input_bytes}-byte limit.",
        retryable=False,
    )
