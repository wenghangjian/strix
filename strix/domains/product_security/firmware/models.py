"""Pydantic contracts for the firmware analysis domain."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


if TYPE_CHECKING:
    from strix.domains.product_security.firmware.errors import FirmwareDomainError


FirmwareAnalysisStatus = Literal[
    "queued",
    "running",
    "created",
    "receiving",
    "analyzing",
    "verified",
    "committing",
    "complete",
    "partial",
    "failed",
    "rejected",
    "timed_out",
    "protocol_error",
    "cancelled",
    "corrupt",
    "detected_unsupported",
    "not_applicable",
    "unclassified",
]


class FirmwarePermission(StrEnum):
    SUMMARY_READ = "firmware.summary.read"
    METADATA_READ = "firmware.metadata.read"
    CONTENT_PREVIEW = "firmware.content.preview"
    SECRET_FINGERPRINT_READ = "firmware.secret.fingerprint.read"  # noqa: S105  # nosec B105
    SECRET_REVEAL = "firmware.secret.reveal"  # noqa: S105  # nosec B105
    WORKER_EXECUTE = "firmware.worker.execute"
    BINARY_INSPECT = "firmware.binary.inspect"
    BINARY_DISASSEMBLE = "firmware.binary.disassemble"
    BINARY_DECOMPILE = "firmware.binary.decompile"
    HINT_CREATE = "firmware.hint.create"
    RECIPE_CREATE = "firmware.recipe.create"
    CANDIDATE_CREATE = "firmware.candidate.create"


def _empty_permissions() -> frozenset[FirmwarePermission]:
    return frozenset()


class FirmwareGeometryContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    page_size: int | None = Field(default=None, gt=0)
    oob_size: int | None = Field(default=None, gt=0)
    pages_per_erase_block: int | None = Field(default=None, gt=0)
    chip_count: int | None = Field(default=None, gt=0)
    interleave: int | None = Field(default=None, gt=0)
    includes_oob: bool | None = None
    byte_order: Literal["little", "big"] | None = None
    base_address: int | None = Field(default=None, ge=0)
    architecture: str | None = None
    expected_filesystem: str | None = None
    source: Literal["user", "datasheet", "known_profile"]


class FirmwareInputArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    input_artifact_id: str = Field(pattern=r"^fw_input_[0-9a-f]{16,64}$")
    scan_id: str = Field(min_length=1)
    project_id: str | None = None
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(gt=0)
    storage_name: str = Field(pattern=r"^[0-9a-f]{64}$")
    label: str | None = None
    source_type: Literal["cli", "upload", "connector", "fixture"]
    source_description: str | None = None
    geometry_contract: FirmwareGeometryContract | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FirmwareAnalysisRecord(BaseModel):
    schema_version: str = "1.0"
    analysis_id: str = Field(pattern=r"^fw_analysis_[0-9a-f]{16,64}$")
    scan_id: str = Field(min_length=1)
    input_artifact_id: str = Field(pattern=r"^fw_input_[0-9a-f]{16,64}$")
    status: FirmwareAnalysisStatus = "queued"
    resume_key: str | None = None
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None


class FirmwareAccessContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    role_id: str = Field(min_length=1)
    allowed_input_artifact_ids: frozenset[str] = Field(default_factory=frozenset)
    permissions: frozenset[FirmwarePermission] = Field(default_factory=_empty_permissions)
    access_profile: str = Field(default="firmware-none-v1", min_length=1)
    issued_by: Literal["scan_runner"]


class FirmwareToolResult[ResultT](BaseModel):
    success: bool
    error_code: str | None = None
    message: str
    retryable: bool = False
    data: ResultT | None = None
    artifact_refs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @classmethod
    def from_error(cls, error: FirmwareDomainError) -> FirmwareToolResult[Any]:
        return FirmwareToolResult[Any](
            success=False,
            error_code=error.error_code,
            message=error.message,
            retryable=error.retryable,
        )
