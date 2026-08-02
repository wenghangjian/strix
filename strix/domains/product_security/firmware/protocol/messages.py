"""Strict FWAP 1.0 JSON messages and P2A manifest contracts."""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError


MAXIMUM_INPUT_BYTES = 512 * 1024 * 1024
MAXIMUM_OUTPUT_BYTES = 1024 * 1024 * 1024
MAXIMUM_FILE_BYTES = 128 * 1024 * 1024
MAXIMUM_REGULAR_FILES = 20_000
MAXIMUM_MANIFEST_BYTES = 8 * 1024 * 1024
MAXIMUM_CHUNK_BYTES = 1024 * 1024
MAXIMUM_ANALYSIS_SECONDS = 180
OUTPUT_STREAM_BASE = 4096

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ANALYSIS_ID_PATTERN = r"^fw_analysis_[0-9a-f]{16,64}$"
INPUT_ID_PATTERN = r"^fw_input_[0-9a-f]{16,64}$"
SESSION_ID_PATTERN = r"^fwap_session_[0-9a-f]{16,64}$"
BLOB_NAME_PATTERN = r"^blob_[0-9]{8}$"
CODE_PATTERN = r"^[A-Z][A-Z0-9_]{0,127}$"

Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]
AnalysisId = Annotated[str, Field(pattern=ANALYSIS_ID_PATTERN)]
InputArtifactId = Annotated[str, Field(pattern=INPUT_ID_PATTERN)]
SessionId = Annotated[str, Field(pattern=SESSION_ID_PATTERN)]
BlobName = Annotated[str, Field(pattern=BLOB_NAME_PATTERN)]
AdapterId = Literal["archive/tar-v1", "archive/zip-v1"]
WorkerStatus = Literal[
    "complete",
    "partial",
    "rejected",
    "detected_unsupported",
    "not_applicable",
    "unclassified",
]


class StrictMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AnalysisLimits(StrictMessage):
    maximum_input_bytes: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    maximum_output_bytes: int = Field(gt=0, le=MAXIMUM_OUTPUT_BYTES)
    maximum_file_bytes: int = Field(gt=0, le=MAXIMUM_FILE_BYTES)
    maximum_regular_files: int = Field(gt=0, le=MAXIMUM_REGULAR_FILES)
    maximum_manifest_bytes: int = Field(gt=0, le=MAXIMUM_MANIFEST_BYTES)
    input_chunk_bytes: int = Field(gt=0, le=MAXIMUM_CHUNK_BYTES)
    output_chunk_bytes: int = Field(gt=0, le=MAXIMUM_CHUNK_BYTES)
    analysis_timeout_seconds: int = Field(gt=0, le=MAXIMUM_ANALYSIS_SECONDS)


class Hello(StrictMessage):
    protocol_major: Literal[1]
    protocol_minor: Literal[0]
    session_id: SessionId
    analysis_id: AnalysisId
    host_implementation: str = Field(min_length=1, max_length=64)
    maximum_frame_payload: Literal[8_388_608]


class HelloAck(StrictMessage):
    protocol_major: Literal[1]
    protocol_minor: Literal[0]
    session_id: SessionId
    worker_build_id: str = Field(min_length=1, max_length=128)
    worker_protocol: Literal["1.0"]
    manifest_schema: Literal["p2a-manifest-1"]
    supported_adapters: list[AdapterId] = Field(min_length=1, max_length=2)
    limits_profile: Literal["p2a-default-v1"]

    @field_validator("supported_adapters")
    @classmethod
    def adapters_are_unique(cls, adapters: list[AdapterId]) -> list[AdapterId]:
        if len(adapters) != len(set(adapters)):
            raise ValueError("supported_adapters must not contain duplicates")
        return adapters


class AnalysisRequest(StrictMessage):
    request_schema: Literal["p2a-request-1"]
    analysis_id: AnalysisId
    input_artifact_id: InputArtifactId
    declared_input_size: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    declared_input_sha256: Sha256
    enabled_adapters: list[AdapterId] = Field(min_length=1, max_length=2)
    limits: AnalysisLimits

    @field_validator("enabled_adapters")
    @classmethod
    def adapters_are_unique(cls, adapters: list[AdapterId]) -> list[AdapterId]:
        if len(adapters) != len(set(adapters)):
            raise ValueError("enabled_adapters must not contain duplicates")
        return adapters


class RequestAccepted(StrictMessage):
    analysis_id: AnalysisId


class InputBegin(StrictMessage):
    analysis_id: AnalysisId
    input_artifact_id: InputArtifactId
    declared_size: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    declared_sha256: Sha256


class InputEnd(StrictMessage):
    analysis_id: AnalysisId
    actual_size: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    actual_sha256: Sha256


class InputAccepted(StrictMessage):
    analysis_id: AnalysisId
    input_artifact_id: InputArtifactId
    actual_size: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    actual_sha256: Sha256


class Progress(StrictMessage):
    analysis_id: AnalysisId
    phase: Literal["input", "analysis", "manifest", "export"]
    progress_percent: int = Field(ge=0, le=100)
    message: str | None = Field(default=None, max_length=256)


class ArchivePathMetadata(StrictMessage):
    display_path: str = Field(min_length=1, max_length=4096)
    canonical_path: str = Field(min_length=1, max_length=4096)
    raw_name_b64: str | None = Field(default=None, max_length=8192)
    path_encoding: str | None = Field(default=None, min_length=1, max_length=64)


class ArchiveMemberMetadata(StrictMessage):
    member_index: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES - 1)
    member_type: Literal["regular_file"]
    declared_size: int = Field(ge=0, le=MAXIMUM_FILE_BYTES)
    actual_size: int = Field(ge=0, le=MAXIMUM_FILE_BYTES)
    compression_method: str = Field(min_length=1, max_length=64)
    crc32: int | None = Field(default=None, ge=0, le=(1 << 32) - 1)
    unix_mode: int | None = Field(default=None, ge=0, le=(1 << 32) - 1)
    uid: int | None = Field(default=None, ge=0, le=(1 << 32) - 1)
    gid: int | None = Field(default=None, ge=0, le=(1 << 32) - 1)
    mtime_utc: AwareDatetime | None = None


class P2AManifestBlob(StrictMessage):
    blob_id: BlobName
    stream_id: int = Field(ge=OUTPUT_STREAM_BASE, le=OUTPUT_STREAM_BASE + MAXIMUM_REGULAR_FILES - 1)
    ordinal: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES - 1)
    generated_storage_name: BlobName
    size_bytes: int = Field(ge=0, le=MAXIMUM_FILE_BYTES)
    sha256: Sha256
    relation: Literal["extracted"]
    parent_input_artifact_id: InputArtifactId
    path: ArchivePathMetadata
    archive: ArchiveMemberMetadata


class P2AManifest(StrictMessage):
    manifest_schema: Literal["p2a-manifest-1"]
    protocol_version: Literal["1.0"]
    analysis_id: AnalysisId
    input_artifact_id: InputArtifactId
    input_size: int = Field(gt=0, le=MAXIMUM_INPUT_BYTES)
    input_sha256: Sha256
    adapter_id: AdapterId | None
    adapter_version: str | None = Field(default=None, min_length=1, max_length=64)
    status: WorkerStatus
    generated_at_utc: AwareDatetime
    worker_build_id: str = Field(min_length=1, max_length=128)
    blob_count: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES)
    total_blob_bytes: int = Field(ge=0, le=MAXIMUM_OUTPUT_BYTES)
    blobs: list[P2AManifestBlob] = Field(max_length=MAXIMUM_REGULAR_FILES)
    warning_codes: list[Annotated[str, Field(pattern=CODE_PATTERN)]] = Field(max_length=256)
    rejected_entry_count: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES)
    ignored_directory_count: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES)
    limits_profile: Literal["p2a-default-v1"]

    @model_validator(mode="after")
    def validate_blob_index(self) -> P2AManifest:
        if self.blob_count != len(self.blobs):
            raise ValueError("blob_count does not match blobs")
        if self.total_blob_bytes != sum(blob.size_bytes for blob in self.blobs):
            raise ValueError("total_blob_bytes does not match blobs")

        canonical_paths: set[str] = set()
        for expected_ordinal, blob in enumerate(self.blobs):
            expected_name = f"blob_{expected_ordinal:08d}"
            if blob.ordinal != expected_ordinal:
                raise ValueError("blob ordinals must be continuous from zero")
            if blob.stream_id != OUTPUT_STREAM_BASE + expected_ordinal:
                raise ValueError("blob stream_id must equal 4096 plus ordinal")
            if not re.fullmatch(BLOB_NAME_PATTERN, blob.generated_storage_name):
                raise ValueError("generated_storage_name has invalid syntax")
            if blob.generated_storage_name != expected_name or blob.blob_id != expected_name:
                raise ValueError("blob identity must match its ordinal")
            if blob.path.canonical_path in canonical_paths:
                raise ValueError("canonical_path values must be unique")
            canonical_paths.add(blob.path.canonical_path)

        zero_blob_statuses = {
            "rejected",
            "detected_unsupported",
            "not_applicable",
            "unclassified",
        }
        if not self.blobs and self.status not in zero_blob_statuses:
            raise ValueError(f"status {self.status!r} does not allow zero blobs")
        return self


class ManifestAccepted(StrictMessage):
    analysis_id: AnalysisId
    manifest_sha256: Sha256
    accepted_blob_count: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES)
    accepted_total_bytes: int = Field(ge=0, le=MAXIMUM_OUTPUT_BYTES)


class BlobBegin(StrictMessage):
    analysis_id: AnalysisId
    blob_id: BlobName
    stream_id: int = Field(ge=OUTPUT_STREAM_BASE, le=OUTPUT_STREAM_BASE + MAXIMUM_REGULAR_FILES - 1)
    declared_size: int = Field(ge=0, le=MAXIMUM_FILE_BYTES)
    declared_sha256: Sha256


class BlobEnd(StrictMessage):
    analysis_id: AnalysisId
    blob_id: BlobName
    actual_size: int = Field(ge=0, le=MAXIMUM_FILE_BYTES)
    actual_sha256: Sha256


class WorkerResult(StrictMessage):
    analysis_id: AnalysisId
    status: WorkerStatus
    adapter_id: AdapterId | None
    manifest_sha256: Sha256
    emitted_blob_count: int = Field(ge=0, le=MAXIMUM_REGULAR_FILES)
    emitted_total_bytes: int = Field(ge=0, le=MAXIMUM_OUTPUT_BYTES)
    warning_codes: list[Annotated[str, Field(pattern=CODE_PATTERN)]] = Field(max_length=256)
    worker_duration_ms: int = Field(ge=0, le=900_000)


class WorkerError(StrictMessage):
    analysis_id: AnalysisId
    error_code: Annotated[str, Field(pattern=CODE_PATTERN)]
    phase: Literal["protocol", "input", "analysis", "manifest", "export", "internal"]
    message: str = Field(min_length=1, max_length=512)
    retryable: bool


class Cancel(StrictMessage):
    analysis_id: AnalysisId
    reason: str = Field(min_length=1, max_length=256)


def encode_json_message(message: BaseModel) -> bytes:
    return json.dumps(
        message.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_json_message[MessageModelT: StrictMessage](
    payload: bytes,
    model_type: type[MessageModelT],
) -> MessageModelT:
    if payload.startswith(b"\xef\xbb\xbf"):
        raise FWAPProtocolError("FWAP_JSON_BOM", "FWAP JSON payload must not contain a BOM.")
    try:
        decoded: Any = json.loads(payload, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise FWAPProtocolError("FWAP_INVALID_JSON", "FWAP JSON payload is invalid.") from exc
    if not isinstance(decoded, dict):
        raise FWAPProtocolError("FWAP_JSON_NOT_OBJECT", "FWAP JSON payload must be an object.")
    try:
        return model_type.model_validate_json(payload)
    except ValidationError as exc:
        raise FWAPProtocolError(
            "FWAP_INVALID_MESSAGE",
            "FWAP JSON payload does not match its message schema.",
        ) from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant {value!r} is not permitted")
