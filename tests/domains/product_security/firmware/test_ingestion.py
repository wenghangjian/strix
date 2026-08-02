from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware import ingestion
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.ingestion import ingest_firmware_inputs
from strix.domains.product_security.firmware.repository import FirmwareRepository


if TYPE_CHECKING:
    from collections.abc import Callable


def _repo(tmp_path: Path) -> FirmwareRepository:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    return repo


def test_ingestion_deduplicates_content_without_exposing_source_path(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"same")
    second.write_bytes(b"same")

    manifest = ingest_firmware_inputs(
        [str(first), str(second)],
        _repo(tmp_path),
        scan_id="scan-1",
    )

    assert len(manifest) == 1
    assert manifest[0].label == "a.bin"
    assert "source_path" not in type(manifest[0]).model_fields


def test_ingestion_reads_from_open_descriptor_when_path_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"original")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"replacement")
    original_open = ingestion._open_input_descriptor

    def open_then_replace(path: Path) -> int:
        descriptor = original_open(path)
        replacement.replace(source)
        return descriptor

    monkeypatch.setattr(ingestion, "_open_input_descriptor", open_then_replace)

    artifact = ingest_firmware_inputs(
        [str(source)],
        _repo(tmp_path),
        scan_id="scan-1",
    )[0]

    assert artifact.sha256 == hashlib.sha256(b"original").hexdigest()


def test_ingestion_rejects_file_growth_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"before")
    original_stream: Callable[..., tuple[str, int]] = ingestion._stream_descriptor

    def grow_then_stream(*args: object, **kwargs: object) -> tuple[str, int]:
        with source.open("ab") as handle:
            handle.write(b"-after-open")
        return original_stream(*args, **kwargs)

    monkeypatch.setattr(ingestion, "_stream_descriptor", grow_then_stream)

    with pytest.raises(FirmwareDomainError) as exc_info:
        ingest_firmware_inputs([str(source)], _repo(tmp_path), scan_id="scan-1")

    assert exc_info.value.error_code == "FIRMWARE_INPUT_CHANGED"


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_ingestion_rejects_non_regular_inputs(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "input"
    if kind == "directory":
        source.mkdir()
    else:
        target = tmp_path / "target.bin"
        target.write_bytes(b"firmware")
        try:
            source.symlink_to(target)
        except OSError:
            pytest.skip("symlinks are unavailable")

    with pytest.raises(FirmwareDomainError) as exc_info:
        ingest_firmware_inputs([str(source)], _repo(tmp_path), scan_id="scan-1")

    assert exc_info.value.error_code == "FIRMWARE_INPUT_INVALID"


def test_ingestion_enforces_streaming_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"12345")

    with pytest.raises(FirmwareDomainError) as exc_info:
        ingest_firmware_inputs(
            [str(source)],
            _repo(tmp_path),
            scan_id="scan-1",
            max_input_bytes=4,
        )

    assert exc_info.value.error_code == "FIRMWARE_INPUT_TOO_LARGE"


def test_ingestion_cleans_staging_after_failure(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"oversized")
    repo = _repo(tmp_path)

    with pytest.raises(FirmwareDomainError):
        ingest_firmware_inputs(
            [str(source)],
            repo,
            scan_id="scan-1",
            max_input_bytes=2,
        )

    assert not any(repo.staging_root.iterdir())
    assert os.path.isfile(source)
