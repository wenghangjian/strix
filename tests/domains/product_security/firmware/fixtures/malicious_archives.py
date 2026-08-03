from __future__ import annotations

import tarfile
from typing import TYPE_CHECKING

from tests.domains.product_security.firmware.fixtures.builders import (
    TarFixtureEntry,
    build_tar,
    patch_tar_declared_size,
)


if TYPE_CHECKING:
    from pathlib import Path


def build_duplicate_path_tar(path: Path) -> Path:
    return build_tar(
        path,
        [
            TarFixtureEntry("a/./b", b"first"),
            TarFixtureEntry("a/b", b"second"),
        ],
    )


def build_special_member_tar(path: Path, member_type: bytes) -> Path:
    linkname = "target" if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
    return build_tar(
        path,
        [TarFixtureEntry("special", member_type=member_type, linkname=linkname)],
    )


def build_dishonest_size_tar(path: Path) -> Path:
    build_tar(
        path,
        [
            TarFixtureEntry("first.bin", b"first"),
            TarFixtureEntry("second.bin", b"short"),
        ],
    )
    patch_tar_declared_size(
        path,
        header_offset=1024,
        declared_size=1024 * 1024,
        truncate_at=2048,
    )
    return path


def build_malformed_pax_tar(path: Path) -> Path:
    long_name = "/".join(["nested"] * 20) + "/config.bin"
    build_tar(
        path,
        [TarFixtureEntry(long_name, b"data")],
    )
    raw = bytearray(path.read_bytes())
    marker = raw.find(b" path=")
    if marker != -1:
        record_start = raw.rfind(b"\n", 0, marker) + 1
        raw[record_start : record_start + 1] = b"x"
    path.write_bytes(raw)
    return path
