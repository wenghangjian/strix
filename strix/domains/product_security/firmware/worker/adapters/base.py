"""Shared immutable contracts for archive preflight and extraction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol


if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from strix.domains.product_security.firmware.worker.limits import WorkerLimits
    from strix.domains.product_security.firmware.worker.paths import CanonicalArchivePath
    from strix.domains.product_security.firmware.worker.staging import WorkerStaging


@dataclass(frozen=True, slots=True)
class PreflightMember:
    member_index: int
    path: CanonicalArchivePath
    declared_size: int
    compression_method: str
    crc32: int | None
    unix_mode: int | None
    uid: int | None
    gid: int | None
    mtime_utc: datetime | None


@dataclass(frozen=True, slots=True)
class AdapterPreflight:
    adapter_id: str
    adapter_version: str
    format_name: str
    limits: WorkerLimits
    members: tuple[PreflightMember, ...]
    total_declared_bytes: int
    ignored_directory_count: int


@dataclass(frozen=True, slots=True)
class ExtractedMember:
    preflight: PreflightMember
    storage_path: Path
    actual_size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class AdapterOutput:
    adapter_id: str
    adapter_version: str
    members: tuple[ExtractedMember, ...]
    total_bytes: int
    ignored_directory_count: int


class ArchiveRejected(RuntimeError):  # noqa: N818 - represents an archive status
    """The complete archive must be rejected without partial output."""


class ArchiveDetectedUnsupported(RuntimeError):  # noqa: N818 - represents an archive status
    """The input is a recognized archive format outside the P2a support set."""


class ArchiveAdapter(Protocol):
    adapter_id: str

    def preflight(self, input_path: Path, limits: WorkerLimits) -> AdapterPreflight: ...

    def extract(
        self,
        input_path: Path,
        preflight: AdapterPreflight,
        staging: WorkerStaging,
    ) -> AdapterOutput: ...
