from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAnalysisRecord,
    FirmwareInputArtifact,
)
from strix.domains.product_security.firmware.repository import FirmwareRepository


if TYPE_CHECKING:
    from pathlib import Path


def _register_input(repo: FirmwareRepository, data: bytes) -> FirmwareInputArtifact:
    digest = hashlib.sha256(data).hexdigest()
    artifact = FirmwareInputArtifact(
        input_artifact_id=f"fw_input_{digest[:16]}",
        scan_id="scan-p2a",
        sha256=digest,
        size_bytes=len(data),
        storage_name=digest,
        source_type="fixture",
    )
    staged = repo.new_staging_path()
    staged.write_bytes(data)
    return repo.register_input(staged, artifact)


def _analysis(artifact: FirmwareInputArtifact) -> FirmwareAnalysisRecord:
    return FirmwareAnalysisRecord(
        analysis_id="fw_analysis_aaaaaaaaaaaaaaaa",
        scan_id=artifact.scan_id,
        input_artifact_id=artifact.input_artifact_id,
        status="created",
    )


@pytest.mark.parametrize(
    "status",
    [
        "created",
        "receiving",
        "analyzing",
        "verified",
        "committing",
        "complete",
        "rejected",
        "failed",
        "timed_out",
        "protocol_error",
        "cancelled",
        "corrupt",
    ],
)
def test_analysis_model_accepts_p2a_persistent_states(status: str) -> None:
    record = FirmwareAnalysisRecord(
        analysis_id="fw_analysis_aaaaaaaaaaaaaaaa",
        scan_id="scan-p2a",
        input_artifact_id="fw_input_bbbbbbbbbbbbbbbb",
        status=status,  # type: ignore[arg-type]
    )

    assert record.status == status


def test_repository_opens_verified_immutable_input_reader(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _register_input(repo, b"immutable-firmware")

    with repo.open_input_reader(artifact.input_artifact_id) as reader:
        assert reader.read(9) == b"immutable"
        assert reader.read() == b"-firmware"


def test_repository_reader_rejects_replaced_cas_symlink(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _register_input(repo, b"trusted")
    blob = repo.blob_path(artifact.sha256)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"trusted")
    blob.unlink()
    blob.symlink_to(outside)

    with pytest.raises(FirmwareDomainError) as exc_info:
        repo.open_input_reader(artifact.input_artifact_id)

    assert exc_info.value.error_code == "FIRMWARE_ARTIFACT_CORRUPT"


def test_transition_analysis_is_atomic_compare_and_set(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _register_input(repo, b"transition")
    analysis = repo.create_analysis(_analysis(artifact))

    repo.transition_analysis(
        analysis.analysis_id,
        expected={"created"},
        target="receiving",
    )

    assert repo.get_analysis(analysis.analysis_id).status == "receiving"
    with pytest.raises(FirmwareDomainError) as exc_info:
        repo.transition_analysis(
            analysis.analysis_id,
            expected={"created"},
            target="analyzing",
        )
    assert exc_info.value.error_code == "FIRMWARE_ANALYSIS_STATE_CONFLICT"
