from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.host.manifest_validator import (
    ExpectedAnalysis,
    HostLimits,
    ManifestReservation,
    validate_manifest,
)
from strix.domains.product_security.firmware.host.output_receiver import HostOutputReceiver
from strix.domains.product_security.firmware.host.staging import HostStaging
from strix.domains.product_security.firmware.protocol.constants import (
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.frame import Frame, FrameEncoder
from strix.domains.product_security.firmware.protocol.messages import (
    ArchiveMemberMetadata,
    ArchivePathMetadata,
    BlobBegin,
    BlobEnd,
    P2AManifest,
    P2AManifestBlob,
    WorkerResult,
    encode_json_message,
)


if TYPE_CHECKING:
    from pathlib import Path


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
INPUT_SHA256 = "c" * 64
BLOB_DATA = (b"firmware-one", b"firmware-two")


def _blob(ordinal: int) -> P2AManifestBlob:
    data = BLOB_DATA[ordinal]
    return P2AManifestBlob(
        blob_id=f"blob_{ordinal:08d}",
        stream_id=4096 + ordinal,
        ordinal=ordinal,
        generated_storage_name=f"blob_{ordinal:08d}",
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        relation="extracted",
        parent_input_artifact_id=INPUT_ID,
        path=ArchivePathMetadata(
            display_path=f"etc/file-{ordinal}",
            canonical_path=f"etc/file-{ordinal}",
            raw_name_b64=None,
            path_encoding=None,
        ),
        archive=ArchiveMemberMetadata(
            member_index=ordinal,
            member_type="regular_file",
            declared_size=len(data),
            actual_size=len(data),
            compression_method="stored",
            crc32=None,
            unix_mode=0o600,
            uid=None,
            gid=None,
            mtime_utc=None,
        ),
    )


def _manifest() -> tuple[bytes, ManifestReservation]:
    blobs = [_blob(0), _blob(1)]
    manifest = P2AManifest(
        manifest_schema="p2a-manifest-1",
        protocol_version="1.0",
        analysis_id=ANALYSIS_ID,
        input_artifact_id=INPUT_ID,
        input_size=10,
        input_sha256=INPUT_SHA256,
        adapter_id="archive/tar-v1",
        adapter_version="1.0",
        status="complete",
        generated_at_utc=datetime(2026, 8, 12, tzinfo=UTC),
        worker_build_id="e" * 64,
        blob_count=2,
        total_blob_bytes=sum(len(data) for data in BLOB_DATA),
        blobs=blobs,
        warning_codes=[],
        rejected_entry_count=0,
        ignored_directory_count=0,
        limits_profile="p2a-default-v1",
    )
    raw = encode_json_message(manifest)
    reservation = validate_manifest(
        raw,
        ExpectedAnalysis(
            analysis_id=ANALYSIS_ID,
            input_artifact_id=INPUT_ID,
            input_size=10,
            input_sha256=INPUT_SHA256,
        ),
        HostLimits(
            maximum_manifest_bytes=8 * 1024 * 1024,
            maximum_output_bytes=1024 * 1024,
            maximum_file_bytes=1024 * 1024,
            maximum_regular_files=10,
        ),
    )
    return raw, reservation


def _json_frame(message_type: MessageType, sequence: int, message: object, stream: int) -> bytes:
    flags = FrameFlags.JSON_PAYLOAD
    if message_type is MessageType.RESULT:
        flags |= FrameFlags.FINAL
    return FrameEncoder.encode(
        Frame(
            message_type=message_type,
            flags=flags,
            stream_id=stream,
            sequence=sequence,
            payload=encode_json_message(message),  # type: ignore[arg-type]
        )
    )


def _chunk_frame(sequence: int, stream: int, payload: bytes) -> bytes:
    return FrameEncoder.encode(
        Frame(
            message_type=MessageType.BLOB_CHUNK,
            flags=FrameFlags.NONE,
            stream_id=stream,
            sequence=sequence,
            payload=payload,
        )
    )


def _begin(blob: P2AManifestBlob, sequence: int) -> bytes:
    return _json_frame(
        MessageType.BLOB_BEGIN,
        sequence,
        BlobBegin(
            analysis_id=ANALYSIS_ID,
            blob_id=blob.blob_id,
            stream_id=blob.stream_id,
            declared_size=blob.size_bytes,
            declared_sha256=blob.sha256,
        ),
        blob.stream_id,
    )


def _end(blob: P2AManifestBlob, sequence: int, *, sha256: str | None = None) -> bytes:
    return _json_frame(
        MessageType.BLOB_END,
        sequence,
        BlobEnd(
            analysis_id=ANALYSIS_ID,
            blob_id=blob.blob_id,
            actual_size=blob.size_bytes,
            actual_sha256=sha256 or blob.sha256,
        ),
        blob.stream_id,
    )


def _result(manifest: P2AManifest, manifest_sha256: str, sequence: int) -> bytes:
    return _json_frame(
        MessageType.RESULT,
        sequence,
        WorkerResult(
            analysis_id=ANALYSIS_ID,
            status=manifest.status,
            adapter_id=manifest.adapter_id,
            manifest_sha256=manifest_sha256,
            emitted_blob_count=manifest.blob_count,
            emitted_total_bytes=manifest.total_blob_bytes,
            warning_codes=manifest.warning_codes,
            worker_duration_ms=25,
        ),
        0,
    )


def _valid_stream() -> tuple[bytes, ManifestReservation, bytes]:
    raw, reservation = _manifest()
    manifest = reservation.manifest
    frames: list[bytes] = []
    sequence = 0
    for blob, data in zip(manifest.blobs, BLOB_DATA, strict=True):
        frames.extend(
            [
                _begin(blob, sequence),
                _chunk_frame(sequence + 1, blob.stream_id, data[:3]),
                _chunk_frame(sequence + 2, blob.stream_id, data[3:]),
                _end(blob, sequence + 3),
            ]
        )
        sequence += 4
    frames.append(_result(manifest, reservation.manifest_sha256, sequence))
    return raw, reservation, b"".join(frames)


def _receiver(
    tmp_path: Path,
    raw: bytes,
    reservation: ManifestReservation,
) -> HostOutputReceiver:
    staging = HostStaging(tmp_path / "staging", ANALYSIS_ID)
    return HostOutputReceiver(
        reservation=reservation,
        manifest_bytes=raw,
        staging=staging,
        starting_sequence=0,
    )


def _fragments(raw: bytes) -> list[bytes]:
    widths = (1, 7, 31, 2, 67)
    chunks: list[bytes] = []
    cursor = 0
    index = 0
    while cursor < len(raw):
        width = widths[index % len(widths)]
        chunks.append(raw[cursor : cursor + width])
        cursor += width
        index += 1
    return chunks


def test_receives_fragmented_blobs_into_private_verified_staging(tmp_path: Path) -> None:
    raw, reservation, stream = _valid_stream()

    output = _receiver(tmp_path, raw, reservation).receive(_fragments(stream))

    assert output.manifest_bytes == raw
    assert output.manifest_sha256 == hashlib.sha256(raw).hexdigest()
    assert output.result.emitted_blob_count == 2
    assert output.container_observation is None
    assert [blob.path.read_bytes() for blob in output.staging_blobs] == list(BLOB_DATA)
    assert [blob.sha256 for blob in output.staging_blobs] == [
        hashlib.sha256(data).hexdigest() for data in BLOB_DATA
    ]
    assert all((blob.path.stat().st_mode & 0o777) == 0o600 for blob in output.staging_blobs)
    assert (output.staging_blobs[0].path.parent.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize(
    ("case", "error_code"),
    [
        ("undeclared", "HOST_BLOB_UNDECLARED"),
        ("wrong_stream", "FWAP_UNKNOWN_STREAM"),
        ("interleaved", "FWAP_UNEXPECTED_MESSAGE"),
        ("overrun", "HOST_BLOB_SIZE_MISMATCH"),
        ("underrun", "HOST_BLOB_SIZE_MISMATCH"),
        ("wrong_hash", "HOST_BLOB_HASH_MISMATCH"),
        ("missing", "HOST_BLOB_MISSING"),
        ("result_mismatch", "HOST_RESULT_MISMATCH"),
        ("result_missing", "FWAP_RESULT_MISSING"),
        ("trailing", "FWAP_TRAILING_OUTPUT"),
        ("exit_mid_blob", "HOST_BLOB_SIZE_MISMATCH"),
    ],
)
def test_rejects_invalid_output_and_removes_complete_staging(
    tmp_path: Path,
    case: str,
    error_code: str,
) -> None:
    raw, reservation, valid = _valid_stream()
    manifest = reservation.manifest
    first = manifest.blobs[0]
    second = manifest.blobs[1]
    if case == "undeclared":
        unknown = first.model_copy(update={"blob_id": "blob_00000009", "ordinal": 9})
        stream = _begin(unknown, 0)
    elif case == "wrong_stream":
        begin = BlobBegin(
            analysis_id=ANALYSIS_ID,
            blob_id=first.blob_id,
            stream_id=first.stream_id,
            declared_size=first.size_bytes,
            declared_sha256=first.sha256,
        )
        stream = _json_frame(MessageType.BLOB_BEGIN, 0, begin, first.stream_id + 1)
    elif case == "interleaved":
        stream = _begin(first, 0) + _begin(second, 1)
    elif case == "overrun":
        stream = _begin(first, 0) + _chunk_frame(1, first.stream_id, BLOB_DATA[0] + b"x")
    elif case == "underrun":
        stream = _begin(first, 0) + _chunk_frame(1, first.stream_id, b"x") + _end(first, 2)
    elif case == "wrong_hash":
        bad = b"x" * len(BLOB_DATA[0])
        stream = _begin(first, 0) + _chunk_frame(1, first.stream_id, bad) + _end(first, 2)
    elif case == "missing":
        stream = _result(manifest, reservation.manifest_sha256, 0)
    elif case == "result_mismatch":
        final = _result(manifest, reservation.manifest_sha256, 8)
        stream = valid[: -len(final)] + _result(manifest, "f" * 64, 8)
    elif case == "result_missing":
        stream = valid[: -len(_result(manifest, reservation.manifest_sha256, 8))]
    elif case == "trailing":
        stream = valid + b"unexpected"
    else:
        stream = _begin(first, 0) + _chunk_frame(1, first.stream_id, b"partial")

    receiver = _receiver(tmp_path, raw, reservation)
    with pytest.raises((FirmwareDomainError, FWAPProtocolError)) as raised:
        receiver.receive(_fragments(stream))

    assert raised.value.error_code == error_code
    assert not any((tmp_path / "staging").rglob("blob_*"))


def test_duplicate_completed_blob_is_rejected(tmp_path: Path) -> None:
    raw, reservation = _manifest()
    first = reservation.manifest.blobs[0]
    completed = (
        _begin(first, 0)
        + _chunk_frame(1, first.stream_id, BLOB_DATA[0])
        + _end(first, 2)
        + _begin(first, 3)
    )

    with pytest.raises(FWAPProtocolError) as raised:
        _receiver(tmp_path, raw, reservation).receive([completed])

    assert raised.value.error_code == "FWAP_DUPLICATE_BLOB"
