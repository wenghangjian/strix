"""Strict two-pass TAR preflight and generated-name extraction."""

from __future__ import annotations

import hashlib
import tarfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never

from strix.domains.product_security.firmware.worker.adapters.base import (
    AdapterOutput,
    AdapterPreflight,
    ArchiveDetectedUnsupported,
    ArchiveRejected,
    ExtractedMember,
    PreflightMember,
)
from strix.domains.product_security.firmware.worker.paths import (
    UnsafeArchivePath,
    canonicalize_archive_path,
)


if TYPE_CHECKING:
    from pathlib import Path
    from typing import IO, BinaryIO

    from strix.domains.product_security.firmware.worker.limits import WorkerLimits
    from strix.domains.product_security.firmware.worker.staging import WorkerStaging


ADAPTER_ID = "archive/tar-v1"
ADAPTER_VERSION = "1.0"
COPY_CHUNK_BYTES = 1024 * 1024


class TarAdapter:
    adapter_id = ADAPTER_ID

    def preflight(self, input_path: Path, limits: WorkerLimits) -> AdapterPreflight:
        format_name = _detect_format(input_path)
        if format_name == "bzip2":
            raise ArchiveDetectedUnsupported("BZIP2-compressed TAR is not supported.")

        members: list[PreflightMember] = []
        canonical_paths: set[str] = set()
        total_declared_bytes = 0
        ignored_directory_count = 0
        try:
            with tarfile.open(input_path, mode="r:*") as archive:
                archive_members = archive.getmembers()
                for member_index, member in enumerate(archive_members):
                    try:
                        path = canonicalize_archive_path(member.name)
                    except UnsafeArchivePath as exc:
                        raise ArchiveRejected("TAR contains an unsafe member path.") from exc
                    if path.canonical_path in canonical_paths:
                        _reject("TAR contains duplicate canonical paths.")
                    canonical_paths.add(path.canonical_path)
                    if member.isdir():
                        ignored_directory_count += 1
                        continue
                    if member.issparse() or not member.isfile():
                        _reject("TAR contains an unsupported member type.")

                    if member.size < 0 or member.size > limits.maximum_file_bytes:
                        _reject("TAR member exceeds the per-file limit.")
                    if len(members) + 1 > limits.maximum_regular_files:
                        _reject("TAR exceeds the regular-file count limit.")
                    total_declared_bytes += member.size
                    if total_declared_bytes > limits.maximum_output_bytes:
                        _reject("TAR exceeds the total output limit.")

                    members.append(
                        PreflightMember(
                            member_index=member_index,
                            path=path,
                            declared_size=member.size,
                            compression_method=format_name,
                            crc32=None,
                            unix_mode=_bounded_uint32(member.mode),
                            uid=_bounded_uint32(member.uid),
                            gid=_bounded_uint32(member.gid),
                            mtime_utc=_safe_mtime(member.mtime),
                        )
                    )
        except ArchiveRejected:
            raise
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise ArchiveRejected("TAR member table is malformed or truncated.") from exc

        if not members:
            raise ArchiveRejected("TAR does not contain a regular file.")
        return AdapterPreflight(
            adapter_id=ADAPTER_ID,
            adapter_version=ADAPTER_VERSION,
            format_name=format_name,
            limits=limits,
            members=tuple(members),
            total_declared_bytes=total_declared_bytes,
            ignored_directory_count=ignored_directory_count,
        )

    def extract(
        self,
        input_path: Path,
        preflight: AdapterPreflight,
        staging: WorkerStaging,
    ) -> AdapterOutput:
        if preflight.adapter_id != ADAPTER_ID:
            raise ArchiveRejected("TAR preflight belongs to another adapter.")
        current = self.preflight(input_path, preflight.limits)
        if current != preflight:
            raise ArchiveRejected("TAR member table changed after preflight.")

        staging.prepare_output()
        extracted: list[ExtractedMember] = []
        total_bytes = 0
        try:
            with tarfile.open(input_path, mode="r:*") as archive:
                archive_members = archive.getmembers()
                for ordinal, planned in enumerate(preflight.members):
                    member = archive_members[planned.member_index]
                    source = archive.extractfile(member)
                    if source is None:
                        _reject("TAR regular member has no data stream.")
                    path, destination = staging.create_output_blob(ordinal)
                    with source, destination:
                        actual_size, sha256 = _copy_member(
                            source,
                            destination,
                            planned.declared_size,
                        )
                    total_bytes += actual_size
                    extracted.append(
                        ExtractedMember(
                            preflight=planned,
                            storage_path=path,
                            actual_size=actual_size,
                            sha256=sha256,
                        )
                    )
        except ArchiveRejected:
            staging.clear_output()
            raise
        except (tarfile.TarError, EOFError, IndexError) as exc:
            staging.clear_output()
            raise ArchiveRejected("TAR data stream is malformed or truncated.") from exc
        except Exception:
            staging.clear_output()
            raise

        if total_bytes != preflight.total_declared_bytes:
            staging.clear_output()
            raise ArchiveRejected("TAR output total does not match preflight.")
        return AdapterOutput(
            adapter_id=ADAPTER_ID,
            adapter_version=ADAPTER_VERSION,
            members=tuple(extracted),
            total_bytes=total_bytes,
            ignored_directory_count=preflight.ignored_directory_count,
        )


def _detect_format(input_path: Path) -> str:
    try:
        with input_path.open("rb") as stream:
            magic = stream.read(6)
    except OSError as exc:
        raise ArchiveRejected("TAR input cannot be read.") from exc
    if magic.startswith(b"BZh"):
        return "bzip2"
    if magic.startswith(b"\x1f\x8b"):
        return "gzip"
    if magic.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    return "tar"


def _bounded_uint32(value: int) -> int:
    if value < 0 or value > (1 << 32) - 1:
        raise ArchiveRejected("TAR numeric metadata is out of range.")
    return value


def _safe_mtime(value: float) -> datetime:
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ArchiveRejected("TAR timestamp metadata is out of range.") from exc


def _copy_member(source: IO[bytes], destination: BinaryIO, declared_size: int) -> tuple[int, str]:
    actual_size = 0
    digest = hashlib.sha256()
    while chunk := source.read(COPY_CHUNK_BYTES):
        actual_size += len(chunk)
        if actual_size > declared_size:
            raise ArchiveRejected("TAR member exceeds its declared size.")
        written = destination.write(chunk)
        if written != len(chunk):
            raise OSError("incomplete worker output write")
        digest.update(chunk)
    if actual_size != declared_size:
        raise ArchiveRejected("TAR member does not match its declared size.")
    return actual_size, digest.hexdigest()


def _reject(message: str) -> Never:
    raise ArchiveRejected(message)
