"""Run-scoped firmware input and queued-analysis service."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAnalysisRecord,
    FirmwareInputArtifact,
)


if TYPE_CHECKING:
    from strix.domains.product_security.firmware.repository import FirmwareRepository


_P1_LIMITATION = "Firmware worker is not available until Phase P2a."


class FirmwareAnalysisService:
    def __init__(self, repository: FirmwareRepository, *, scan_id: str) -> None:
        self.repository = repository
        self.scan_id = scan_id

    def list_inputs(self) -> list[FirmwareInputArtifact]:
        return self.repository.list_inputs(scan_id=self.scan_id)

    def get_input(self, input_artifact_id: str) -> FirmwareInputArtifact:
        artifact = self.repository.get_input(input_artifact_id)
        self._require_scan(artifact.scan_id)
        return artifact

    def queue_analysis(self, input_artifact_id: str) -> FirmwareAnalysisRecord:
        artifact = self.get_input(input_artifact_id)
        digest = hashlib.sha256(
            f"{self.scan_id}\0{artifact.input_artifact_id}\0p1".encode()
        ).hexdigest()
        return self.repository.create_analysis(
            FirmwareAnalysisRecord(
                analysis_id=f"fw_analysis_{digest[:16]}",
                scan_id=self.scan_id,
                input_artifact_id=artifact.input_artifact_id,
                status="queued",
                limitations=[_P1_LIMITATION],
            )
        )

    def list_analyses(self) -> list[FirmwareAnalysisRecord]:
        return self.repository.list_analyses(scan_id=self.scan_id)

    def get_analysis(self, analysis_id: str) -> FirmwareAnalysisRecord:
        record = self.repository.get_analysis(analysis_id)
        self._require_scan(record.scan_id)
        return record

    def get_summary(self, analysis_id: str) -> FirmwareAnalysisRecord:
        return self.get_analysis(analysis_id)

    def _require_scan(self, owner_scan_id: str) -> None:
        if owner_scan_id != self.scan_id:
            raise FirmwareDomainError(
                "FIRMWARE_ACCESS_DENIED",
                "Firmware artifact belongs to a different scan.",
                retryable=False,
            )
