from __future__ import annotations

import io
import tarfile
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
