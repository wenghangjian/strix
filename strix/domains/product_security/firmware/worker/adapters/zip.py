"""Strict two-pass ZIP central-directory preflight and extraction."""

from __future__ import annotations

import hashlib
import stat
import struct
import zipfile
import zlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never

from strix.domains.product_security.firmware.worker.adapters.base import (
    AdapterOutput,
    AdapterPreflight,
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


ADAPTER_ID = "archive/zip-v1"
ADAPTER_VERSION = "1.0"
COPY_CHUNK_BYTES = 1024 * 1024
ZIP64_EXTRA_ID = 0x0001
_ALLOWED_FLAGS = 0x0006 | 0x0008 | 0x0800
_METHOD_NAMES = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflated",
}


class ZipAdapter:
    adapter_id = ADAPTER_ID

    def preflight(self, input_path: Path, limits: WorkerLimits) -> AdapterPreflight:
        members: list[PreflightMember] = []
        canonical_paths: set[str] = set()
        header_offsets: set[int] = set()
        total_declared_bytes = 0
        ignored_directory_count = 0
        try:
            with zipfile.ZipFile(input_path, mode="r", allowZip64=True) as archive:
                archive_members = archive.infolist()
                for member_index, member in enumerate(archive_members):
                    inspected = _inspect_member(
                        member,
                        member_index,
                        limits,
                        canonical_paths,
                        header_offsets,
                    )
                    if inspected is None:
                        ignored_directory_count += 1
                        continue
                    if len(members) + 1 > limits.maximum_regular_files:
                        _reject("ZIP exceeds the regular-file count limit.")
                    total_declared_bytes += inspected.declared_size
                    if total_declared_bytes > limits.maximum_output_bytes:
                        _reject("ZIP exceeds the total output limit.")
                    members.append(inspected)
        except ArchiveRejected:
            raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, OSError) as exc:
            raise ArchiveRejected("ZIP central directory is malformed or truncated.") from exc

        if not members:
            raise ArchiveRejected("ZIP does not contain a regular file.")
        return AdapterPreflight(
            adapter_id=ADAPTER_ID,
            adapter_version=ADAPTER_VERSION,
            format_name="zip",
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
            raise ArchiveRejected("ZIP preflight belongs to another adapter.")
        current = self.preflight(input_path, preflight.limits)
        if current != preflight:
            raise ArchiveRejected("ZIP central directory changed after preflight.")

        staging.prepare_output()
        extracted: list[ExtractedMember] = []
        total_bytes = 0
        try:
            with zipfile.ZipFile(input_path, mode="r", allowZip64=True) as archive:
                archive_members = archive.infolist()
                for ordinal, planned in enumerate(preflight.members):
                    member = archive_members[planned.member_index]
                    path, destination = staging.create_output_blob(ordinal)
                    with archive.open(member, mode="r") as source, destination:
                        actual_size, sha256 = _copy_member(
                            source,
                            destination,
                            planned.declared_size,
                            _require_crc(planned),
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
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            NotImplementedError,
            RuntimeError,
            EOFError,
            IndexError,
            zlib.error,
        ) as exc:
            staging.clear_output()
            raise ArchiveRejected("ZIP data stream is malformed or truncated.") from exc
        except Exception:
            staging.clear_output()
            raise

        if total_bytes != preflight.total_declared_bytes:
            staging.clear_output()
            raise ArchiveRejected("ZIP output total does not match preflight.")
        return AdapterOutput(
            adapter_id=ADAPTER_ID,
            adapter_version=ADAPTER_VERSION,
            members=tuple(extracted),
            total_bytes=total_bytes,
            ignored_directory_count=preflight.ignored_directory_count,
        )


def _validate_flags_and_method(member: zipfile.ZipInfo) -> None:
    if member.flag_bits & 0x0001:
        _reject("Encrypted ZIP entries are forbidden.")
    if member.flag_bits & ~_ALLOWED_FLAGS:
        _reject("ZIP entry uses unsupported general-purpose flags.")
    if member.compress_type not in _METHOD_NAMES:
        _reject("ZIP entry uses an unsupported compression method.")
    if member.compress_type != zipfile.ZIP_DEFLATED and member.flag_bits & 0x0006:
        _reject("ZIP entry uses invalid compression-option flags.")


def _inspect_member(
    member: zipfile.ZipInfo,
    member_index: int,
    limits: WorkerLimits,
    canonical_paths: set[str],
    header_offsets: set[int],
) -> PreflightMember | None:
    _validate_flags_and_method(member)
    _validate_extra_fields(member.extra)
    try:
        path = canonicalize_archive_path(member.orig_filename)
    except UnsafeArchivePath as exc:
        raise ArchiveRejected("ZIP contains an unsafe member path.") from exc
    if path.canonical_path in canonical_paths:
        _reject("ZIP contains duplicate canonical paths.")
    canonical_paths.add(path.canonical_path)
    if member.header_offset < 0 or member.header_offset in header_offsets:
        _reject("ZIP contains an invalid local-header offset.")
    header_offsets.add(member.header_offset)

    unix_mode = _validate_member_type(member)
    if member.is_dir():
        return None
    if member.file_size < 0 or member.file_size > limits.maximum_file_bytes:
        _reject("ZIP member exceeds the per-file limit.")
    if member.compress_size < 0 or member.compress_size > limits.maximum_input_bytes:
        _reject("ZIP member has an invalid compressed size.")
    if member.CRC < 0 or member.CRC > (1 << 32) - 1:
        _reject("ZIP member CRC is out of range.")
    return PreflightMember(
        member_index=member_index,
        path=path,
        declared_size=member.file_size,
        compression_method=_METHOD_NAMES[member.compress_type],
        crc32=member.CRC,
        unix_mode=unix_mode,
        uid=None,
        gid=None,
        mtime_utc=_safe_mtime(member.date_time),
    )


def _validate_extra_fields(extra: bytes) -> None:
    cursor = 0
    seen_zip64 = False
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            _reject("ZIP entry contains a truncated extra-field header.")
        header_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        field_end = cursor + field_size
        if field_end > len(extra):
            _reject("ZIP entry contains a truncated extra field.")
        if header_id == ZIP64_EXTRA_ID:
            if seen_zip64 or field_size == 0 or field_size > 28 or field_size % 4:
                _reject("ZIP64 extra field is malformed.")
            seen_zip64 = True
        cursor = field_end


def _validate_member_type(member: zipfile.ZipInfo) -> int | None:
    if member.create_system != 3:
        return None
    unix_mode = (member.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if member.is_dir():
        if file_type not in {0, stat.S_IFDIR}:
            _reject("ZIP directory has invalid Unix file metadata.")
        return unix_mode
    if file_type not in {0, stat.S_IFREG}:
        _reject("ZIP contains a non-regular Unix file type.")
    return unix_mode


def _safe_mtime(value: tuple[int, int, int, int, int, int]) -> datetime:
    try:
        return datetime(*value, tzinfo=UTC)
    except ValueError as exc:
        raise ArchiveRejected("ZIP timestamp metadata is out of range.") from exc


def _copy_member(
    source: IO[bytes],
    destination: BinaryIO,
    declared_size: int,
    expected_crc: int,
) -> tuple[int, str]:
    actual_size = 0
    digest = hashlib.sha256()
    crc32 = 0
    while chunk := source.read(COPY_CHUNK_BYTES):
        actual_size += len(chunk)
        if actual_size > declared_size:
            _reject("ZIP member exceeds its declared size.")
        written = destination.write(chunk)
        if written != len(chunk):
            raise OSError("incomplete worker output write")
        digest.update(chunk)
        crc32 = zlib.crc32(chunk, crc32)
    if actual_size != declared_size:
        _reject("ZIP member does not match its declared size.")
    if crc32 & 0xFFFFFFFF != expected_crc:
        _reject("ZIP member does not match its declared CRC.")
    return actual_size, digest.hexdigest()


def _require_crc(member: PreflightMember) -> int:
    if member.crc32 is None:
        _reject("ZIP preflight member is missing its CRC.")
    return member.crc32


def _reject(message: str) -> Never:
    raise ArchiveRejected(message)
