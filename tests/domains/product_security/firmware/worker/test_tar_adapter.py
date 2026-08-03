from __future__ import annotations

import hashlib
import io
import stat
import tarfile
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.protocol.messages import AnalysisLimits
from strix.domains.product_security.firmware.worker.adapters.base import (
    ArchiveDetectedUnsupported,
    ArchiveRejected,
)
from strix.domains.product_security.firmware.worker.adapters.tar import TarAdapter
from strix.domains.product_security.firmware.worker.limits import WorkerLimits
from strix.domains.product_security.firmware.worker.staging import WorkerStaging
from tests.domains.product_security.firmware.fixtures.builders import (
    TarFixtureEntry,
    build_tar,
)
from tests.domains.product_security.firmware.fixtures.malicious_archives import (
    build_dishonest_size_tar,
    build_duplicate_path_tar,
    build_malformed_pax_tar,
    build_special_member_tar,
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


@pytest.mark.parametrize("compression", ["plain", "gz", "xz"])
def test_valid_tar_formats_preflight_and_extract_all_regular_files(
    tmp_path: Path,
    compression: str,
) -> None:
    suffix = {"plain": ".tar", "gz": ".tar.gz", "xz": ".tar.xz"}[compression]
    archive = build_tar(
        tmp_path / f"valid{suffix}",
        [
            TarFixtureEntry("etc", member_type=tarfile.DIRTYPE),
            TarFixtureEntry("etc/config", b"value=1"),
            TarFixtureEntry("empty.bin", b""),
        ],
        compression=compression,  # type: ignore[arg-type]
    )
    adapter = TarAdapter()

    preflight = adapter.preflight(archive, _limits())
    output = adapter.extract(archive, preflight, _staging(tmp_path))

    assert adapter.adapter_id == "archive/tar-v1"
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


def test_valid_pax_path_is_supported(tmp_path: Path) -> None:
    name = "/".join(["nested"] * 20) + "/config.bin"
    archive = build_tar(tmp_path / "pax.tar", [TarFixtureEntry(name, b"pax")])

    preflight = TarAdapter().preflight(archive, _limits())

    assert preflight.members[0].path.canonical_path == name


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
def test_unsafe_tar_paths_are_rejected(tmp_path: Path, name: str) -> None:
    archive = build_tar(tmp_path / "unsafe.tar", [TarFixtureEntry(name, b"bad")])

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


def test_duplicate_canonical_tar_path_is_rejected(tmp_path: Path) -> None:
    archive = build_duplicate_path_tar(tmp_path / "duplicate.tar")

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(
    "entries",
    [
        [
            TarFixtureEntry("../unsafe", member_type=tarfile.DIRTYPE),
            TarFixtureEntry("safe", b"data"),
        ],
        [
            TarFixtureEntry("same", member_type=tarfile.DIRTYPE),
            TarFixtureEntry("same/.", member_type=tarfile.DIRTYPE),
            TarFixtureEntry("safe", b"data"),
        ],
    ],
)
def test_directory_paths_follow_the_same_policy(
    tmp_path: Path,
    entries: list[TarFixtureEntry],
) -> None:
    archive = build_tar(tmp_path / "unsafe-directory.tar", entries)

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(
    "member_type",
    [
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
        tarfile.GNUTYPE_SPARSE,
        b"V",
    ],
)
def test_special_and_unknown_tar_members_are_rejected(
    tmp_path: Path,
    member_type: bytes,
) -> None:
    archive = build_special_member_tar(tmp_path / "special.tar", member_type)

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


@pytest.mark.parametrize(
    ("limit_updates", "entries"),
    [
        ({"maximum_file_bytes": 3}, [TarFixtureEntry("large", b"four")]),
        (
            {"maximum_output_bytes": 5},
            [TarFixtureEntry("one", b"123"), TarFixtureEntry("two", b"456")],
        ),
        (
            {"maximum_regular_files": 1},
            [TarFixtureEntry("one", b"1"), TarFixtureEntry("two", b"2")],
        ),
    ],
)
def test_tar_preflight_reserves_all_limits(
    tmp_path: Path,
    limit_updates: dict[str, int],
    entries: list[TarFixtureEntry],
) -> None:
    archive = build_tar(tmp_path / "limited.tar", entries)

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits(**limit_updates))


def test_directory_only_tar_is_rejected(tmp_path: Path) -> None:
    archive = build_tar(
        tmp_path / "directories.tar",
        [TarFixtureEntry("only-dir", member_type=tarfile.DIRTYPE)],
    )

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


def test_bzip2_tar_is_detected_unsupported(tmp_path: Path) -> None:
    archive = build_tar(
        tmp_path / "unsupported.tar.bz2",
        [TarFixtureEntry("file", b"data")],
        compression="bz2",
    )

    with pytest.raises(ArchiveDetectedUnsupported):
        TarAdapter().preflight(archive, _limits())


@pytest.mark.parametrize("builder", [build_malformed_pax_tar, build_dishonest_size_tar])
def test_malformed_or_dishonest_tar_is_rejected(
    tmp_path: Path,
    builder: object,
) -> None:
    archive = builder(tmp_path / "malformed.tar")  # type: ignore[operator]
    adapter = TarAdapter()

    with pytest.raises(ArchiveRejected):
        preflight = adapter.preflight(archive, _limits())
        adapter.extract(archive, preflight, _staging(tmp_path))


def test_truncated_tar_is_rejected(tmp_path: Path) -> None:
    archive = build_tar(tmp_path / "truncated.tar", [TarFixtureEntry("file", b"data")])
    archive.write_bytes(archive.read_bytes()[:700])

    with pytest.raises(ArchiveRejected):
        TarAdapter().preflight(archive, _limits())


def test_member_failure_clears_all_output_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = build_tar(
        tmp_path / "read-failure.tar",
        [TarFixtureEntry("first", b"first"), TarFixtureEntry("second", b"second")],
    )
    adapter = TarAdapter()
    staging = _staging(tmp_path)
    original_extractfile = tarfile.TarFile.extractfile

    def truncate_second_member(
        opened_archive: tarfile.TarFile,
        member: tarfile.TarInfo | str,
    ) -> object:
        if isinstance(member, tarfile.TarInfo) and member.name == "second":
            return io.BytesIO(b"")
        return original_extractfile(opened_archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", truncate_second_member)

    with pytest.raises(ArchiveRejected):
        preflight = adapter.preflight(archive, _limits())
        adapter.extract(archive, preflight, staging)

    assert not staging.output_root.exists()


def test_tar_adapter_never_uses_filesystem_extraction_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = build_tar(tmp_path / "safe.tar", [TarFixtureEntry("file", b"data")])

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("filesystem extraction API was called")

    monkeypatch.setattr(tarfile.TarFile, "extract", forbidden)
    monkeypatch.setattr(tarfile.TarFile, "extractall", forbidden)
    adapter = TarAdapter()
    preflight = adapter.preflight(archive, _limits())

    output = adapter.extract(archive, preflight, _staging(tmp_path))

    assert output.members[0].storage_path.read_bytes() == b"data"
