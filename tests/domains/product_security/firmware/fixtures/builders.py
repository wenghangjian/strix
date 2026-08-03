from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from pathlib import Path


TarCompression = Literal["plain", "gz", "xz", "bz2"]


@dataclass(frozen=True, slots=True)
class TarFixtureEntry:
    name: str
    data: bytes = b""
    member_type: bytes = tarfile.REGTYPE
    linkname: str = ""
    pax_headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ZipFixtureEntry:
    name: str
    data: bytes = b""
    compression: int = zipfile.ZIP_DEFLATED
    unix_mode: int | None = None
    extra: bytes = b""


def build_tar(
    path: Path,
    entries: list[TarFixtureEntry],
    *,
    compression: TarCompression = "plain",
) -> Path:
    modes = {"plain": "w", "gz": "w:gz", "xz": "w:xz", "bz2": "w:bz2"}
    with tarfile.open(path, modes[compression], format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.type = entry.member_type
            info.mode = 0o640
            info.uid = 1000
            info.gid = 1000
            info.mtime = 1_700_000_000
            info.linkname = entry.linkname
            info.pax_headers = entry.pax_headers
            if entry.member_type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                info.size = len(entry.data)
                archive.addfile(info, io.BytesIO(entry.data))
            else:
                archive.addfile(info)
    return path


def patch_tar_declared_size(
    path: Path,
    *,
    header_offset: int,
    declared_size: int,
    truncate_at: int | None = None,
) -> None:
    raw = bytearray(path.read_bytes())
    raw[header_offset + 124 : header_offset + 136] = f"{declared_size:011o}\0".encode()
    raw[header_offset + 148 : header_offset + 156] = b"        "
    checksum = sum(raw[header_offset : header_offset + 512])
    raw[header_offset + 148 : header_offset + 156] = f"{checksum:06o}\0 ".encode()
    if truncate_at is not None:
        del raw[truncate_at:]
    path.write_bytes(raw)


def build_zip(
    path: Path,
    entries: list[ZipFixtureEntry],
    *,
    force_zip64: bool = False,
) -> Path:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for entry in entries:
            info = zipfile.ZipInfo(entry.name, date_time=(2024, 1, 2, 3, 4, 6))
            info.compress_type = entry.compression
            info.create_system = 3
            info.extra = entry.extra
            mode = entry.unix_mode
            if mode is None:
                mode = (
                    (stat.S_IFDIR | 0o750) if entry.name.endswith("/") else (stat.S_IFREG | 0o640)
                )
            info.external_attr = mode << 16
            if force_zip64 and not entry.name.endswith("/"):
                with archive.open(info, "w", force_zip64=True) as destination:
                    destination.write(entry.data)
            else:
                archive.writestr(info, entry.data)
    return path
