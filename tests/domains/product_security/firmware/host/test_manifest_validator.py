from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.host.manifest_validator import (
    ExpectedAnalysis,
    HostLimits,
    validate_manifest,
)


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
INPUT_SHA256 = "c" * 64
BLOB_SHA256 = "d" * 64


def _blob(ordinal: int = 0, *, path: str = "etc/config") -> dict[str, Any]:
    return {
        "blob_id": f"blob_{ordinal:08d}",
        "stream_id": 4096 + ordinal,
        "ordinal": ordinal,
        "generated_storage_name": f"blob_{ordinal:08d}",
        "size_bytes": 7,
        "sha256": BLOB_SHA256,
        "relation": "extracted",
        "parent_input_artifact_id": INPUT_ID,
        "path": {
            "display_path": path,
            "canonical_path": path,
            "raw_name_b64": None,
            "path_encoding": None,
        },
        "archive": {
            "member_index": ordinal,
            "member_type": "regular_file",
            "declared_size": 7,
            "actual_size": 7,
            "compression_method": "stored",
            "crc32": None,
            "unix_mode": 0o600,
            "uid": None,
            "gid": None,
            "mtime_utc": None,
        },
    }


def _manifest(*, blobs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    manifest_blobs = [_blob()] if blobs is None else blobs
    return {
        "manifest_schema": "p2a-manifest-1",
        "protocol_version": "1.0",
        "analysis_id": ANALYSIS_ID,
        "input_artifact_id": INPUT_ID,
        "input_size": 10,
        "input_sha256": INPUT_SHA256,
        "adapter_id": "archive/tar-v1",
        "adapter_version": "1.0",
        "status": "complete",
        "generated_at_utc": datetime(2026, 8, 4, tzinfo=UTC).isoformat(),
        "worker_build_id": "e" * 64,
        "blob_count": len(manifest_blobs),
        "total_blob_bytes": sum(int(blob["size_bytes"]) for blob in manifest_blobs),
        "blobs": manifest_blobs,
        "warning_codes": [],
        "rejected_entry_count": 0,
        "ignored_directory_count": 0,
        "limits_profile": "p2a-default-v1",
    }


def _raw(manifest: dict[str, Any]) -> bytes:
    return json.dumps(
        manifest,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _expected(**changes: object) -> ExpectedAnalysis:
    values: dict[str, object] = {
        "analysis_id": ANALYSIS_ID,
        "input_artifact_id": INPUT_ID,
        "input_size": 10,
        "input_sha256": INPUT_SHA256,
    }
    values.update(changes)
    return ExpectedAnalysis(**values)  # type: ignore[arg-type]


def _limits(**changes: int) -> HostLimits:
    values = {
        "maximum_manifest_bytes": 8 * 1024 * 1024,
        "maximum_output_bytes": 1024 * 1024 * 1024,
        "maximum_file_bytes": 128 * 1024 * 1024,
        "maximum_regular_files": 20_000,
    }
    values.update(changes)
    return HostLimits(**values)


def _assert_rejected(
    manifest: dict[str, Any],
    error_code: str,
    *,
    expected: ExpectedAnalysis | None = None,
    limits: HostLimits | None = None,
) -> None:
    with pytest.raises(FirmwareDomainError) as raised:
        validate_manifest(
            _raw(manifest),
            expected or _expected(),
            limits or _limits(),
        )
    assert raised.value.error_code == error_code
    assert not raised.value.retryable


def test_valid_manifest_reserves_exact_raw_hash_counts_and_streams() -> None:
    manifest = _manifest(blobs=[_blob(), _blob(1, path="usr/bin/tool")])
    raw = _raw(manifest) + b"\n"

    reservation = validate_manifest(raw, _expected(), _limits())

    assert reservation.manifest_sha256 == hashlib.sha256(raw).hexdigest()
    assert reservation.blob_count == 2
    assert reservation.total_bytes == 14
    assert reservation.streams == frozenset({4096, 4097})
    assert reservation.manifest.analysis_id == ANALYSIS_ID


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analysis_id", "fw_analysis_ffffffffffffffff"),
        ("input_artifact_id", "fw_input_ffffffffffffffff"),
        ("input_size", 11),
        ("input_sha256", "f" * 64),
    ],
)
def test_manifest_identity_must_match_expected_analysis(field: str, value: object) -> None:
    _assert_rejected(
        _manifest(),
        "HOST_MANIFEST_IDENTITY_MISMATCH",
        expected=_expected(**{field: value}),
    )


def test_raw_manifest_size_uses_host_limit_before_schema_parsing() -> None:
    with pytest.raises(FirmwareDomainError) as raised:
        validate_manifest(b"{" + b" " * 32, _expected(), _limits(maximum_manifest_bytes=16))

    assert raised.value.error_code == "HOST_MANIFEST_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "limits",
    [
        {"maximum_regular_files": 1},
        {"maximum_output_bytes": 13},
        {"maximum_file_bytes": 6},
    ],
)
def test_host_limits_are_applied_independently(limits: dict[str, int]) -> None:
    manifest = _manifest(blobs=[_blob(), _blob(1, path="usr/bin/tool")])

    _assert_rejected(
        manifest,
        "HOST_MANIFEST_LIMIT_EXCEEDED",
        limits=_limits(**limits),
    )


@pytest.mark.parametrize("field", ["blob_id", "stream_id"])
def test_duplicate_blob_ids_and_streams_are_rejected(field: str) -> None:
    blobs = [_blob(), _blob(1, path="usr/bin/tool")]
    blobs[1][field] = blobs[0][field]

    _assert_rejected(_manifest(blobs=blobs), "HOST_MANIFEST_DUPLICATE_ID")


def test_generated_storage_name_must_be_host_generated_basename() -> None:
    blob = _blob()
    blob["generated_storage_name"] = "../../escape"

    _assert_rejected(_manifest(blobs=[blob]), "HOST_MANIFEST_SCHEMA_INVALID")


@pytest.mark.parametrize(
    ("display_path", "canonical_path"),
    [
        ("../etc/passwd", "../etc/passwd"),
        ("etc/./config", "etc/./config"),
        ("etc\\config", "etc\\config"),
        ("safe/path", "different/path"),
        ("a" * 256, "a" * 256),
    ],
)
def test_archive_paths_are_revalidated_by_host(
    display_path: str,
    canonical_path: str,
) -> None:
    blob = _blob(path=display_path)
    blob["path"]["canonical_path"] = canonical_path

    _assert_rejected(_manifest(blobs=[blob]), "HOST_MANIFEST_PATH_INVALID")


@pytest.mark.parametrize(
    "status",
    ["rejected", "detected_unsupported", "not_applicable", "unclassified"],
)
def test_non_output_statuses_cannot_declare_blobs(status: str) -> None:
    manifest = _manifest()
    manifest["status"] = status

    _assert_rejected(manifest, "HOST_MANIFEST_SCHEMA_INVALID")


def test_blob_parent_and_actual_size_must_match_manifest_contract() -> None:
    wrong_parent = _blob()
    wrong_parent["parent_input_artifact_id"] = "fw_input_ffffffffffffffff"
    _assert_rejected(_manifest(blobs=[wrong_parent]), "HOST_MANIFEST_IDENTITY_MISMATCH")

    wrong_size = _blob()
    wrong_size["archive"]["actual_size"] = 6
    _assert_rejected(_manifest(blobs=[wrong_size]), "HOST_MANIFEST_SCHEMA_INVALID")
