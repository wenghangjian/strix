from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAccessContext,
    FirmwareAnalysisRecord,
    FirmwareGeometryContract,
    FirmwareInputArtifact,
    FirmwarePermission,
    FirmwareToolResult,
)


def test_access_context_is_runner_issued_and_immutable() -> None:
    access = FirmwareAccessContext(
        scan_id="scan-1",
        agent_id="agent-1",
        role_id="firmware_analyst",
        allowed_input_artifact_ids=frozenset({"fw_input_abc"}),
        permissions=frozenset({FirmwarePermission.METADATA_READ}),
        access_profile="firmware-analyst-v1",
        issued_by="scan_runner",
    )

    with pytest.raises(ValidationError):
        access.agent_id = "agent-2"  # type: ignore[misc]


def test_access_context_rejects_untrusted_issuer() -> None:
    with pytest.raises(ValidationError):
        FirmwareAccessContext(
            scan_id="scan-1",
            agent_id="agent-1",
            role_id="firmware_analyst",
            issued_by="agent",  # type: ignore[arg-type]
        )


def test_geometry_requires_declared_source() -> None:
    with pytest.raises(ValidationError):
        FirmwareGeometryContract(page_size=2048)  # type: ignore[call-arg]


def test_geometry_rejects_non_positive_dimensions() -> None:
    with pytest.raises(ValidationError):
        FirmwareGeometryContract(page_size=0, source="user")


def test_input_artifact_validates_sha256_and_hides_host_path() -> None:
    artifact = FirmwareInputArtifact(
        input_artifact_id="fw_input_aaaaaaaaaaaaaaaa",
        scan_id="scan-1",
        sha256="a" * 64,
        size_bytes=4,
        storage_name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        label="firmware.bin",
        source_type="cli",
    )

    assert artifact.created_at.tzinfo == UTC
    assert "source_path" not in type(artifact).model_fields

    with pytest.raises(ValidationError):
        FirmwareInputArtifact.model_validate(
            {**artifact.model_dump(), "sha256": "not-a-hash"},
        )


def test_analysis_record_uses_explicit_queued_state() -> None:
    record = FirmwareAnalysisRecord(
        analysis_id="fw_analysis_bbbbbbbbbbbbbbbb",
        scan_id="scan-1",
        input_artifact_id="fw_input_aaaaaaaaaaaaaaaa",
        status="queued",
        created_at=datetime.now(UTC),
    )

    assert record.status == "queued"
    assert record.completed_at is None


def test_firmware_error_serializes_common_tool_envelope() -> None:
    error = FirmwareDomainError(
        "FIRMWARE_ACCESS_DENIED",
        "Firmware access is denied.",
        retryable=False,
    )

    result = FirmwareToolResult.from_error(error)

    assert result.model_dump(mode="json") == {
        "success": False,
        "error_code": "FIRMWARE_ACCESS_DENIED",
        "message": "Firmware access is denied.",
        "retryable": False,
        "data": None,
        "artifact_refs": [],
        "warnings": [],
    }
