from __future__ import annotations

import tarfile
from typing import TYPE_CHECKING

from tests.domains.product_security.firmware.fixtures.builders import (
    TarFixtureEntry,
    ZipFixtureEntry,
    build_tar,
    build_zip,
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


def build_duplicate_path_zip(path: Path) -> Path:
    return build_zip(
        path,
        [ZipFixtureEntry("a/./b", b"first"), ZipFixtureEntry("a/b", b"second")],
    )


def patch_zip_flags(path: Path, flags: int) -> None:
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    raw[local + 6 : local + 8] = flags.to_bytes(2, "little")
    raw[central + 8 : central + 10] = flags.to_bytes(2, "little")
    path.write_bytes(raw)


def patch_zip_method(path: Path, method: int) -> None:
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    raw[local + 8 : local + 10] = method.to_bytes(2, "little")
    raw[central + 10 : central + 12] = method.to_bytes(2, "little")
    path.write_bytes(raw)


def patch_zip_crc(path: Path, crc32: int) -> None:
    raw = bytearray(path.read_bytes())
    central = raw.find(b"PK\x01\x02")
    raw[central + 16 : central + 20] = crc32.to_bytes(4, "little")
    path.write_bytes(raw)


def patch_zip_uncompressed_size(path: Path, size: int) -> None:
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    raw[local + 22 : local + 26] = size.to_bytes(4, "little")
    raw[central + 24 : central + 28] = size.to_bytes(4, "little")
    path.write_bytes(raw)


def patch_zip_filename_byte(path: Path, original: bytes, replacement: bytes) -> None:
    if len(original) != 1 or len(replacement) != 1:
        raise ValueError("ZIP filename patch bytes must each have length one")
    raw = bytearray(path.read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    local_name_length = int.from_bytes(raw[local + 26 : local + 28], "little")
    central_name_length = int.from_bytes(raw[central + 28 : central + 30], "little")
    local_name = raw[local + 30 : local + 30 + local_name_length]
    central_name = raw[central + 46 : central + 46 + central_name_length]
    local_index = local_name.index(original)
    central_index = central_name.index(original)
    raw[local + 30 + local_index] = replacement[0]
    raw[central + 46 + central_index] = replacement[0]
    path.write_bytes(raw)
