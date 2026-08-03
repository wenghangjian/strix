from __future__ import annotations

import hashlib
import io
import stat
import zipfile
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.protocol.messages import AnalysisLimits
from strix.domains.product_security.firmware.worker.adapters.base import ArchiveRejected
from strix.domains.product_security.firmware.worker.adapters.zip import ZipAdapter
from strix.domains.product_security.firmware.worker.limits import WorkerLimits
from strix.domains.product_security.firmware.worker.staging import WorkerStaging
from tests.domains.product_security.firmware.fixtures.builders import (
    ZipFixtureEntry,
    build_zip,
)
from tests.domains.product_security.firmware.fixtures.malicious_archives import (
    build_duplicate_path_zip,
    patch_zip_crc,
    patch_zip_filename_byte,
    patch_zip_flags,
    patch_zip_method,
    patch_zip_uncompressed_size,
)


if TYPE_CHECKING:
    from pathlib import Path


def _limits(**updates: int) -> WorkerLimits:
    values = {
        "maximum_input_bytes": 512 * 1024 * 1024,
        "maximum_output_bytes": 1024 * 1024 * 1024,
        "maximum_file_bytes": 128 * 1024 * 1024,
        "maximum_regular_files": 20_000,
        "maximum_manifest_bytes": 8 * 1024 * 1024,
        "input_chunk_bytes": 1024 * 1024,
        "output_chunk_bytes": 1024 * 1024,
        "analysis_timeout_seconds": 180,
    }
    values.update(updates)
    return WorkerLimits.from_analysis_limits(AnalysisLimits.model_validate(values))


def _staging(tmp_path: Path) -> WorkerStaging:
    root = tmp_path / "work"
    root.mkdir()
    return WorkerStaging(root)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_valid_zip_methods_preflight_and_extract_all_regular_files(
    tmp_path: Path,
    compression: int,
) -> None:
    archive = build_zip(
        tmp_path / "valid.zip",
        [
            ZipFixtureEntry("etc/", compression=compression),
            ZipFixtureEntry("etc/config", b"value=1", compression),
            ZipFixtureEntry("empty.bin", b"", compression),
        ],
    )
    adapter = ZipAdapter()

    preflight = adapter.preflight(archive, _limits())
    output = adapter.extract(archive, preflight, _staging(tmp_path))

    assert adapter.adapter_id == "archive/zip-v1"
    assert preflight.ignored_directory_count == 1
    assert [member.path.canonical_path for member in preflight.members] == [
        "etc/config",
        "empty.bin",
    ]
    assert [member.actual_size for member in output.members] == [7, 0]
    assert output.total_bytes == 7
    assert output.members[0].sha256 == hashlib.sha256(b"value=1").hexdigest()
    for ordinal, member in enumerate(output.members):
        assert member.storage_path.name == f"blob_{ordinal:08d}"
        assert stat.S_IMODE(member.storage_path.stat().st_mode) == 0o600


def test_forced_zip64_entry_is_supported(tmp_path: Path) -> None:
    archive = build_zip(
        tmp_path / "zip64.zip",
        [ZipFixtureEntry("nested/data.bin", b"zip64")],
        force_zip64=True,
    )

    preflight = ZipAdapter().preflight(archive, _limits())

    assert preflight.members[0].declared_size == 5


@pytest.mark.parametrize(
    "name",
    [
        "/etc/passwd",
        "../etc/passwd",
        "a/../../etc/passwd",
        r"..\etc\passwd",
        r"C:\Windows\system.ini",
        r"\\server\share\file",
    ],
)
def test_unsafe_zip_paths_are_rejected(tmp_path: Path, name: str) -> None:
    archive = build_zip(tmp_path / "unsafe.zip", [ZipFixtureEntry(name, b"bad")])

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_duplicate_canonical_zip_path_is_rejected(tmp_path: Path) -> None:
    archive = build_duplicate_path_zip(tmp_path / "duplicate.zip")

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_nul_in_raw_zip_filename_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "nul-name.zip", [ZipFixtureEntry("a_b", b"data")])
    patch_zip_filename_byte(archive, b"_", b"\x00")

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(
    "entries",
    [
        [ZipFixtureEntry("../unsafe/"), ZipFixtureEntry("safe", b"data")],
        [
            ZipFixtureEntry("same/"),
            ZipFixtureEntry("same/./"),
            ZipFixtureEntry("safe", b"data"),
        ],
    ],
)
def test_zip_directory_paths_follow_the_same_policy(
    tmp_path: Path,
    entries: list[ZipFixtureEntry],
) -> None:
    archive = build_zip(tmp_path / "unsafe-directory.zip", entries)

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_unsupported_zip_compression_is_rejected(
    tmp_path: Path,
    compression: int,
) -> None:
    archive = build_zip(
        tmp_path / "unsupported.zip",
        [ZipFixtureEntry("file", b"data", compression)],
    )

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_encrypted_zip_flag_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "encrypted.zip", [ZipFixtureEntry("file", b"data")])
    patch_zip_flags(archive, 0x0001)

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(("flags", "method"), [(0x4000, None), (None, 99)])
def test_unknown_zip_flags_and_methods_are_rejected(
    tmp_path: Path,
    flags: int | None,
    method: int | None,
) -> None:
    archive = build_zip(tmp_path / "unknown.zip", [ZipFixtureEntry("file", b"data")])
    if flags is not None:
        patch_zip_flags(archive, flags)
    if method is not None:
        patch_zip_method(archive, method)

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_malformed_zip_extra_field_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(
        tmp_path / "bad-extra.zip",
        [ZipFixtureEntry("file", b"data", extra=b"\x01\x00\x08")],
    )

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_unix_symlink_entry_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(
        tmp_path / "symlink.zip",
        [ZipFixtureEntry("link", b"target", unix_mode=stat.S_IFLNK | 0o777)],
    )

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(
    ("limit_updates", "entries"),
    [
        ({"maximum_file_bytes": 3}, [ZipFixtureEntry("large", b"four")]),
        (
            {"maximum_output_bytes": 5},
            [ZipFixtureEntry("one", b"123"), ZipFixtureEntry("two", b"456")],
        ),
        (
            {"maximum_regular_files": 1},
            [ZipFixtureEntry("one", b"1"), ZipFixtureEntry("two", b"2")],
        ),
    ],
)
def test_zip_preflight_reserves_all_limits(
    tmp_path: Path,
    limit_updates: dict[str, int],
    entries: list[ZipFixtureEntry],
) -> None:
    archive = build_zip(tmp_path / "limited.zip", entries)

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits(**limit_updates))


def test_directory_only_zip_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "directories.zip", [ZipFixtureEntry("only-dir/")])

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_crc_mismatch_is_rejected_and_clears_output(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "bad-crc.zip", [ZipFixtureEntry("file", b"data")])
    patch_zip_crc(archive, 0)
    adapter = ZipAdapter()
    staging = _staging(tmp_path)
    preflight = adapter.preflight(archive, _limits())

    with pytest.raises(ArchiveRejected):
        adapter.extract(archive, preflight, staging)

    assert not staging.output_root.exists()


def test_dishonest_zip_size_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "dishonest.zip", [ZipFixtureEntry("file", b"data")])
    patch_zip_uncompressed_size(archive, 5)
    adapter = ZipAdapter()

    with pytest.raises(ArchiveRejected):
        preflight = adapter.preflight(archive, _limits())
        adapter.extract(archive, preflight, _staging(tmp_path))


def test_truncated_central_directory_is_rejected(tmp_path: Path) -> None:
    archive = build_zip(tmp_path / "truncated.zip", [ZipFixtureEntry("file", b"data")])
    archive.write_bytes(archive.read_bytes()[:-12])

    with pytest.raises(ArchiveRejected):
        ZipAdapter().preflight(archive, _limits())


def test_member_failure_clears_all_output_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = build_zip(
        tmp_path / "read-failure.zip",
        [ZipFixtureEntry("first", b"first"), ZipFixtureEntry("second", b"second")],
    )
    adapter = ZipAdapter()
    staging = _staging(tmp_path)
    original_open = zipfile.ZipFile.open

    def truncate_second_member(
        opened_archive: zipfile.ZipFile,
        member: zipfile.ZipInfo | str,
        *args: object,
        **kwargs: object,
    ) -> object:
        if isinstance(member, zipfile.ZipInfo) and member.filename == "second":
            return io.BytesIO(b"")
        return original_open(opened_archive, member, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(zipfile.ZipFile, "open", truncate_second_member)
    preflight = adapter.preflight(archive, _limits())

    with pytest.raises(ArchiveRejected):
        adapter.extract(archive, preflight, staging)

    assert not staging.output_root.exists()


def test_zip_adapter_never_uses_filesystem_extraction_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = build_zip(tmp_path / "safe.zip", [ZipFixtureEntry("file", b"data")])

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("filesystem extraction API was called")

    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    adapter = ZipAdapter()
    preflight = adapter.preflight(archive, _limits())

    output = adapter.extract(archive, preflight, _staging(tmp_path))

    assert output.members[0].storage_path.read_bytes() == b"data"
