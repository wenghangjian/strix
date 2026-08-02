from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.messages import (
    AnalysisLimits,
    ArchiveMemberMetadata,
    ArchivePathMetadata,
    Hello,
    P2AManifest,
    P2AManifestBlob,
    decode_json_message,
    encode_json_message,
)


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
SHA256 = "c" * 64


def _blob(*, ordinal: int = 0, canonical_path: str = "etc/config") -> P2AManifestBlob:
    return P2AManifestBlob(
        blob_id=f"blob_{ordinal:08d}",
        stream_id=4096 + ordinal,
        ordinal=ordinal,
        generated_storage_name=f"blob_{ordinal:08d}",
        size_bytes=7,
        sha256=SHA256,
        relation="extracted",
        parent_input_artifact_id=INPUT_ID,
        path=ArchivePathMetadata(
            display_path=canonical_path,
            canonical_path=canonical_path,
            raw_name_b64=None,
            path_encoding=None,
        ),
        archive=ArchiveMemberMetadata(
            member_index=ordinal,
            member_type="regular_file",
            declared_size=7,
            actual_size=7,
            compression_method="stored",
            crc32=None,
            unix_mode=0o600,
            uid=None,
            gid=None,
            mtime_utc=None,
        ),
    )


def _manifest_dict(*, blobs: list[P2AManifestBlob] | None = None) -> dict[str, object]:
    manifest_blobs = [_blob()] if blobs is None else blobs
    return {
        "manifest_schema": "p2a-manifest-1",
        "protocol_version": "1.0",
        "analysis_id": ANALYSIS_ID,
        "input_artifact_id": INPUT_ID,
        "input_size": 10,
        "input_sha256": SHA256,
        "adapter_id": "archive/tar-v1",
        "adapter_version": "1.0",
        "status": "complete",
        "generated_at_utc": datetime(2026, 8, 2, tzinfo=UTC),
        "worker_build_id": "d" * 64,
        "blob_count": len(manifest_blobs),
        "total_blob_bytes": sum(blob.size_bytes for blob in manifest_blobs),
        "blobs": manifest_blobs,
        "warning_codes": [],
        "rejected_entry_count": 0,
        "ignored_directory_count": 0,
        "limits_profile": "p2a-default-v1",
    }


def test_unknown_fields_and_integer_coercion_are_rejected() -> None:
    fields = {
        "protocol_major": 1,
        "protocol_minor": 0,
        "session_id": "fwap_session_aaaaaaaaaaaaaaaa",
        "analysis_id": ANALYSIS_ID,
        "host_implementation": "strix",
        "maximum_frame_payload": 8 * 1024 * 1024,
    }

    with pytest.raises(ValidationError):
        Hello.model_validate({**fields, "unexpected": True})
    with pytest.raises(ValidationError):
        Hello.model_validate({**fields, "maximum_frame_payload": "8388608"})


@pytest.mark.parametrize("sha256", ["A" * 64, "a" * 63, "g" * 64])
def test_sha256_must_be_exactly_64_lowercase_hex_characters(sha256: str) -> None:
    data = _manifest_dict()
    data["input_sha256"] = sha256

    with pytest.raises(ValidationError):
        P2AManifest.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maximum_input_bytes", 0),
        ("maximum_input_bytes", 536_870_913),
        ("maximum_regular_files", 20_001),
        ("input_chunk_bytes", 1_048_577),
        ("analysis_timeout_seconds", True),
    ],
)
def test_analysis_limits_are_strict_and_bounded(field: str, value: object) -> None:
    limits = {
        "maximum_input_bytes": 536_870_912,
        "maximum_output_bytes": 1_073_741_824,
        "maximum_file_bytes": 134_217_728,
        "maximum_regular_files": 20_000,
        "maximum_manifest_bytes": 8_388_608,
        "input_chunk_bytes": 1_048_576,
        "output_chunk_bytes": 1_048_576,
        "analysis_timeout_seconds": 180,
    }
    limits[field] = value

    with pytest.raises(ValidationError):
        AnalysisLimits.model_validate(limits)


def test_json_encoding_is_canonical_utf8() -> None:
    hello = Hello(
        protocol_major=1,
        protocol_minor=0,
        session_id="fwap_session_aaaaaaaaaaaaaaaa",
        analysis_id=ANALYSIS_ID,
        host_implementation="strix-安全",
        maximum_frame_payload=8 * 1024 * 1024,
    )

    encoded = encode_json_message(hello)

    assert encoded.startswith(b'{"analysis_id"')
    assert b" " not in encoded
    assert "安全".encode() in encoded
    assert decode_json_message(encoded, Hello) == hello


@pytest.mark.parametrize("payload", [b"\xef\xbb\xbf{}", b"[]", b"null", b"NaN"])
def test_json_decoder_rejects_bom_and_non_object_values(payload: bytes) -> None:
    with pytest.raises(FWAPProtocolError):
        decode_json_message(payload, Hello)


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    [
        ({"blob_count": 2}, "blob_count"),
        ({"total_blob_bytes": 8}, "total_blob_bytes"),
    ],
)
def test_manifest_rejects_inconsistent_counts(
    mutation: dict[str, object],
    expected_fragment: str,
) -> None:
    data = {**_manifest_dict(), **mutation}

    with pytest.raises(ValidationError, match=expected_fragment):
        P2AManifest.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ordinal", 1),
        ("stream_id", 4097),
        ("generated_storage_name", "../../escape"),
        ("blob_id", "blob_1"),
    ],
)
def test_manifest_rejects_invalid_blob_identity(field: str, value: object) -> None:
    blob = _blob().model_copy(update={field: value})

    with pytest.raises(ValidationError):
        P2AManifest.model_validate(_manifest_dict(blobs=[blob]))


def test_manifest_rejects_duplicate_canonical_paths() -> None:
    blobs = [_blob(), _blob(ordinal=1)]

    with pytest.raises(ValidationError, match="canonical_path"):
        P2AManifest.model_validate(_manifest_dict(blobs=blobs))


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_manifest_rejects_zero_blobs_for_output_statuses(status: str) -> None:
    data = _manifest_dict(blobs=[])
    data["status"] = status

    with pytest.raises(ValidationError, match="zero blobs"):
        P2AManifest.model_validate(data)


@pytest.mark.parametrize(
    "status",
    ["rejected", "detected_unsupported", "not_applicable", "unclassified"],
)
def test_manifest_allows_zero_blobs_for_non_output_statuses(status: str) -> None:
    data = _manifest_dict(blobs=[])
    data["status"] = status
    data["adapter_id"] = None
    data["adapter_version"] = None

    assert P2AManifest.model_validate(data).blob_count == 0
