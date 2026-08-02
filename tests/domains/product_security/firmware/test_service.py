from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import FirmwareInputArtifact
from strix.domains.product_security.firmware.repository import FirmwareRepository
from strix.domains.product_security.firmware.service import FirmwareAnalysisService


if TYPE_CHECKING:
    from pathlib import Path


def _registered_input(repo: FirmwareRepository, *, scan_id: str) -> FirmwareInputArtifact:
    data = f"firmware-{scan_id}".encode()
    digest = hashlib.sha256(data).hexdigest()
    artifact = FirmwareInputArtifact(
        input_artifact_id=f"fw_input_{digest[:16]}",
        scan_id=scan_id,
        sha256=digest,
        size_bytes=len(data),
        storage_name=digest,
        source_type="fixture",
    )
    staged = repo.new_staging_path()
    staged.write_bytes(data)
    return repo.register_input(staged, artifact)


def test_service_queues_analysis_idempotently(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _registered_input(repo, scan_id="scan-1")
    service = FirmwareAnalysisService(repo, scan_id="scan-1")

    first = service.queue_analysis(artifact.input_artifact_id)
    second = service.queue_analysis(artifact.input_artifact_id)

    assert first == second
    assert first.status == "queued"
    assert first.limitations == ["Firmware worker is not available until Phase P2a."]
    assert service.list_analyses() == [first]


def test_service_denies_cross_scan_input(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _registered_input(repo, scan_id="scan-other")
    service = FirmwareAnalysisService(repo, scan_id="scan-1")

    with pytest.raises(FirmwareDomainError) as exc_info:
        service.queue_analysis(artifact.input_artifact_id)

    assert exc_info.value.error_code == "FIRMWARE_ACCESS_DENIED"


def test_service_lists_only_current_scan_inputs(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    expected = _registered_input(repo, scan_id="scan-1")
    _registered_input(repo, scan_id="scan-other")

    service = FirmwareAnalysisService(repo, scan_id="scan-1")

    assert service.list_inputs() == [expected]
