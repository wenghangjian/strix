"""Strict host-side validation and reservation of untrusted worker manifests."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, NoReturn, TypeGuard, cast

from pydantic import ValidationError

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.messages import P2AManifest


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_OUTPUT_STATUSES = frozenset({"complete", "partial"})
_ADAPTER_STATUSES = frozenset({"complete", "partial", "rejected", "detected_unsupported"})
_NO_ADAPTER_STATUSES = frozenset({"not_applicable", "unclassified"})
_MAXIMUM_COMPONENT_BYTES = 255
_MAXIMUM_CANONICAL_PATH_BYTES = 4096


@dataclass(frozen=True, slots=True)
class ExpectedAnalysis:
    analysis_id: str
    input_artifact_id: str
    input_size: int
    input_sha256: str


@dataclass(frozen=True, slots=True)
class HostLimits:
    maximum_manifest_bytes: int
    maximum_output_bytes: int
    maximum_file_bytes: int
    maximum_regular_files: int

    def __post_init__(self) -> None:
        for value in (
            self.maximum_manifest_bytes,
            self.maximum_output_bytes,
            self.maximum_file_bytes,
            self.maximum_regular_files,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("Host manifest limits must be positive integers.")


@dataclass(frozen=True, slots=True)
class ManifestReservation:
    manifest: P2AManifest
    manifest_sha256: str
    blob_count: int
    total_bytes: int
    streams: frozenset[int]


def validate_manifest(
    raw: bytes,
    expected: ExpectedAnalysis,
    limits: HostLimits,
) -> ManifestReservation:
    if len(raw) > limits.maximum_manifest_bytes:
        _reject(
            "HOST_MANIFEST_LIMIT_EXCEEDED",
            "Worker manifest exceeds the Host byte limit.",
        )
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    decoded = _decode_manifest_object(raw)
    _reject_duplicate_blob_identities(decoded)
    try:
        manifest = P2AManifest.model_validate_json(raw)
    except ValidationError as exc:
        raise FirmwareDomainError(
            "HOST_MANIFEST_SCHEMA_INVALID",
            "Worker manifest does not match the P2a schema.",
            retryable=False,
        ) from exc

    _validate_identity(manifest, expected)
    _validate_limits(manifest, limits)
    _validate_status(manifest)
    for blob in manifest.blobs:
        if blob.parent_input_artifact_id != expected.input_artifact_id:
            _reject(
                "HOST_MANIFEST_IDENTITY_MISMATCH",
                "Worker manifest blob parent does not match the expected input.",
            )
        if blob.archive.actual_size != blob.size_bytes:
            _reject(
                "HOST_MANIFEST_SCHEMA_INVALID",
                "Worker manifest blob sizes are inconsistent.",
            )
        _validate_path(
            display_path=blob.path.display_path,
            canonical_path=blob.path.canonical_path,
            raw_name_b64=blob.path.raw_name_b64,
            path_encoding=blob.path.path_encoding,
        )

    return ManifestReservation(
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        blob_count=len(manifest.blobs),
        total_bytes=sum(blob.size_bytes for blob in manifest.blobs),
        streams=frozenset(blob.stream_id for blob in manifest.blobs),
    )


def _decode_manifest_object(raw: bytes) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        _reject("HOST_MANIFEST_SCHEMA_INVALID", "Worker manifest JSON is invalid.")
    try:
        decoded: Any = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise FirmwareDomainError(
            "HOST_MANIFEST_SCHEMA_INVALID",
            "Worker manifest JSON is invalid.",
            retryable=False,
        ) from exc
    if not isinstance(decoded, dict):
        _reject("HOST_MANIFEST_SCHEMA_INVALID", "Worker manifest JSON must be an object.")
    return cast("dict[str, Any]", decoded)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant {value!r} is not permitted")


def _is_json_list(value: object) -> TypeGuard[list[Any]]:
    return isinstance(value, list)


def _reject_duplicate_blob_identities(decoded: dict[str, Any]) -> None:
    blobs: object = decoded.get("blobs")
    if not _is_json_list(blobs):
        return
    blob_ids: set[str] = set()
    stream_ids: set[int] = set()
    for candidate in blobs:
        if not isinstance(candidate, dict):
            continue
        blob = cast("dict[str, Any]", candidate)
        blob_id = blob.get("blob_id")
        if isinstance(blob_id, str):
            if blob_id in blob_ids:
                _reject("HOST_MANIFEST_DUPLICATE_ID", "Worker manifest repeats a blob ID.")
            blob_ids.add(blob_id)
        stream_id = blob.get("stream_id")
        if type(stream_id) is int:
            if stream_id in stream_ids:
                _reject("HOST_MANIFEST_DUPLICATE_ID", "Worker manifest repeats a stream ID.")
            stream_ids.add(stream_id)


def _validate_identity(manifest: P2AManifest, expected: ExpectedAnalysis) -> None:
    if (
        manifest.analysis_id != expected.analysis_id
        or manifest.input_artifact_id != expected.input_artifact_id
        or manifest.input_size != expected.input_size
        or manifest.input_sha256 != expected.input_sha256
    ):
        _reject(
            "HOST_MANIFEST_IDENTITY_MISMATCH",
            "Worker manifest does not match the expected analysis input.",
        )


def _validate_limits(manifest: P2AManifest, limits: HostLimits) -> None:
    if (
        len(manifest.blobs) > limits.maximum_regular_files
        or manifest.total_blob_bytes > limits.maximum_output_bytes
        or any(blob.size_bytes > limits.maximum_file_bytes for blob in manifest.blobs)
    ):
        _reject(
            "HOST_MANIFEST_LIMIT_EXCEEDED",
            "Worker manifest exceeds an independent Host output limit.",
        )


def _validate_status(manifest: P2AManifest) -> None:
    if manifest.status not in _OUTPUT_STATUSES and manifest.blobs:
        _reject(
            "HOST_MANIFEST_SCHEMA_INVALID",
            "Worker manifest status cannot declare output blobs.",
        )
    if manifest.status in _ADAPTER_STATUSES and (
        manifest.adapter_id is None or manifest.adapter_version is None
    ):
        _reject(
            "HOST_MANIFEST_SCHEMA_INVALID",
            "Worker manifest status requires an adapter identity.",
        )
    if manifest.status in _NO_ADAPTER_STATUSES and (
        manifest.adapter_id is not None or manifest.adapter_version is not None
    ):
        _reject(
            "HOST_MANIFEST_SCHEMA_INVALID",
            "Worker manifest status forbids an adapter identity.",
        )


def _validate_path(
    *,
    display_path: str,
    canonical_path: str,
    raw_name_b64: str | None,
    path_encoding: str | None,
) -> None:
    try:
        expected_canonical = _canonicalize_display_path(display_path)
        canonical_size = len(canonical_path.encode("utf-8"))
    except (UnicodeEncodeError, ValueError) as exc:
        _reject_path(exc)
    if canonical_path != expected_canonical or canonical_size > _MAXIMUM_CANONICAL_PATH_BYTES:
        _reject_path()
    if (raw_name_b64 is None) != (path_encoding is None):
        _reject_path()
    if raw_name_b64 is not None:
        try:
            base64.b64decode(raw_name_b64, validate=True)
        except ValueError as exc:
            _reject_path(exc)

def _canonicalize_display_path(display_path: str) -> str:
    if not display_path or "\x00" in display_path:
        raise ValueError("empty or NUL path")
    normalized = unicodedata.normalize("NFC", display_path)
    if normalized != display_path:
        raise ValueError("display path is not NFC")
    security_path = normalized.replace("\\", "/")
    if security_path.startswith("/"):
        raise ValueError("absolute path")

    components: list[str] = []
    for component in security_path.split("/"):
        if component in {"", "."}:
            continue
        if component == ".." or (not components and _DRIVE_PREFIX.match(component)):
            raise ValueError("unsafe path component")
        if len(component.encode("utf-8")) > _MAXIMUM_COMPONENT_BYTES:
            raise ValueError("path component too long")
        components.append(component)
    if not components:
        raise ValueError("path has no components")
    canonical = "/".join(components)
    if len(canonical.encode("utf-8")) > _MAXIMUM_CANONICAL_PATH_BYTES:
        raise ValueError("canonical path too long")
    return canonical


def _reject_path(cause: Exception | None = None) -> NoReturn:
    error = FirmwareDomainError(
        "HOST_MANIFEST_PATH_INVALID",
        "Worker manifest contains invalid archive path metadata.",
        retryable=False,
    )
    if cause is None:
        raise error
    raise error from cause


def _reject(error_code: str, message: str) -> NoReturn:
    raise FirmwareDomainError(error_code, message, retryable=False)
