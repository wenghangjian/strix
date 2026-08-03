from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.protocol.constants import (
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.frame import (
    Frame,
    FrameDecoder,
    FrameEncoder,
)
from strix.domains.product_security.firmware.protocol.messages import (
    AnalysisLimits,
    AnalysisRequest,
    BlobBegin,
    BlobEnd,
    Hello,
    InputBegin,
    InputEnd,
    ManifestAccepted,
    P2AManifest,
    WorkerResult,
    decode_json_message,
    encode_json_message,
)
from strix.domains.product_security.firmware.worker.adapters.base import AdapterOutput
from strix.domains.product_security.firmware.worker.adapters.tar import TarAdapter
from strix.domains.product_security.firmware.worker.adapters.zip import ZipAdapter
from strix.domains.product_security.firmware.worker.export import (
    WorkerExporter,
    WorkerExportError,
)
from strix.domains.product_security.firmware.worker.limits import WorkerLimits
from strix.domains.product_security.firmware.worker.manifest import (
    LocalStatus,
    analyze_archive,
    build_manifest,
    select_archive_adapter,
)
from strix.domains.product_security.firmware.worker.session import WorkerSession
from strix.domains.product_security.firmware.worker.staging import (
    StagedInput,
    WorkerStaging,
)
from tests.domains.product_security.firmware.fixtures.builders import (
    TarFixtureEntry,
    ZipFixtureEntry,
    build_tar,
    build_zip,
)


if TYPE_CHECKING:
    from pathlib import Path


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
SESSION_ID = "fwap_session_cccccccccccccccc"
WORKER_BUILD_ID = "d" * 64
GENERATED_AT = datetime(2026, 8, 3, tzinfo=UTC)


def _limits() -> WorkerLimits:
    return WorkerLimits(
        maximum_input_bytes=512 * 1024 * 1024,
        maximum_output_bytes=1024 * 1024 * 1024,
        maximum_file_bytes=128 * 1024 * 1024,
        maximum_regular_files=20_000,
        maximum_manifest_bytes=8 * 1024 * 1024,
        input_chunk_bytes=1024 * 1024,
        output_chunk_bytes=1024 * 1024,
        analysis_timeout_seconds=180,
    )


def _request(input_bytes: bytes, *, enabled: list[str] | None = None) -> AnalysisRequest:
    return AnalysisRequest(
        request_schema="p2a-request-1",
        analysis_id=ANALYSIS_ID,
        input_artifact_id=INPUT_ID,
        declared_input_size=len(input_bytes),
        declared_input_sha256=hashlib.sha256(input_bytes).hexdigest(),
        enabled_adapters=enabled or ["archive/tar-v1", "archive/zip-v1"],  # type: ignore[arg-type]
        limits=AnalysisLimits.model_validate(_limits().model_dump()),
    )


def _worker_staging(tmp_path: Path) -> WorkerStaging:
    root = tmp_path / "work"
    root.mkdir()
    return WorkerStaging(root)


def _analyzed_tar(tmp_path: Path) -> tuple[AnalysisRequest, StagedInput, AdapterOutput]:
    archive = build_tar(
        tmp_path / "input.tar",
        [
            TarFixtureEntry("etc", member_type=tarfile.DIRTYPE),
            TarFixtureEntry("etc/config", b"value=1"),
            TarFixtureEntry("bin/tool", b"tool"),
        ],
    )
    input_bytes = archive.read_bytes()
    request = _request(input_bytes)
    staged = StagedInput(
        path=archive,
        size=len(input_bytes),
        sha256=hashlib.sha256(input_bytes).hexdigest(),
    )
    analyzed = analyze_archive(
        input_path=archive,
        enabled_adapters=request.enabled_adapters,
        limits=_limits(),
        staging=_worker_staging(tmp_path),
    )
    assert isinstance(analyzed, AdapterOutput)
    return request, staged, analyzed


def test_selects_tar_zip_neither_and_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tar_path = build_tar(tmp_path / "input.tar", [TarFixtureEntry("file", b"tar")])
    zip_path = build_zip(tmp_path / "input.zip", [ZipFixtureEntry("file", b"zip")])
    raw_path = tmp_path / "input.bin"
    raw_path.write_bytes(b"not an archive")

    assert isinstance(
        select_archive_adapter(tar_path, ["archive/tar-v1", "archive/zip-v1"]),
        TarAdapter,
    )
    assert isinstance(
        select_archive_adapter(zip_path, ["archive/tar-v1", "archive/zip-v1"]),
        ZipAdapter,
    )
    neither = select_archive_adapter(raw_path, ["archive/tar-v1", "archive/zip-v1"])
    assert isinstance(neither, LocalStatus)
    assert neither.status == "not_applicable"

    monkeypatch.setattr("tarfile.is_tarfile", lambda _path: True)
    monkeypatch.setattr("zipfile.is_zipfile", lambda _path: True)
    ambiguous = select_archive_adapter(raw_path, ["archive/tar-v1", "archive/zip-v1"])
    assert isinstance(ambiguous, LocalStatus)
    assert ambiguous.status == "unclassified"
    assert ambiguous.warning_codes == ("WORKER_FORMAT_AMBIGUOUS",)


def test_safety_rejection_becomes_zero_blob_rejected_status(tmp_path: Path) -> None:
    archive = build_tar(
        tmp_path / "unsafe.tar",
        [TarFixtureEntry("../escape", b"bad")],
    )

    analyzed = analyze_archive(
        input_path=archive,
        enabled_adapters=["archive/tar-v1", "archive/zip-v1"],
        limits=_limits(),
        staging=_worker_staging(tmp_path),
    )

    assert analyzed == LocalStatus(
        status="rejected",
        adapter_id="archive/tar-v1",
        adapter_version="1.0",
        warning_codes=("WORKER_TAR_REJECTED",),
        rejected_entry_count=1,
        ignored_directory_count=0,
    )


def test_manifest_fields_are_deterministic_and_use_generated_blob_ids(tmp_path: Path) -> None:
    request, staged, analyzed = _analyzed_tar(tmp_path)

    first = build_manifest(
        request=request,
        staged_input=staged,
        analysis=analyzed,
        worker_build_id=WORKER_BUILD_ID,
        generated_at_utc=GENERATED_AT,
    )
    second = build_manifest(
        request=request,
        staged_input=staged,
        analysis=analyzed,
        worker_build_id=WORKER_BUILD_ID,
        generated_at_utc=GENERATED_AT,
    )

    assert first == second
    assert first.status == "complete"
    assert first.adapter_id == "archive/tar-v1"
    assert first.blob_count == 2
    assert first.total_blob_bytes == 11
    assert [blob.blob_id for blob in first.blobs] == ["blob_00000000", "blob_00000001"]
    assert [blob.stream_id for blob in first.blobs] == [4096, 4097]
    assert [blob.ordinal for blob in first.blobs] == [0, 1]
    assert first.blobs[0].path.canonical_path == "etc/config"
    assert first.blobs[0].archive.actual_size == 7
    assert first.ignored_directory_count == 1


@dataclass(frozen=True, slots=True)
class _SentFrame:
    message_type: MessageType
    payload: bytes
    stream_id: int
    flags: FrameFlags


def test_export_waits_for_acceptance_then_streams_sequential_verified_blobs(
    tmp_path: Path,
) -> None:
    request, staged, analyzed = _analyzed_tar(tmp_path)
    manifest = build_manifest(
        request=request,
        staged_input=staged,
        analysis=analyzed,
        worker_build_id=WORKER_BUILD_ID,
        generated_at_utc=GENERATED_AT,
    )
    sent: list[_SentFrame] = []

    def send_frame(
        message_type: MessageType,
        payload: bytes,
        stream_id: int,
        flags: FrameFlags,
    ) -> None:
        sent.append(_SentFrame(message_type, payload, stream_id, flags))

    exporter = WorkerExporter(
        manifest=manifest,
        output=analyzed,
        output_chunk_bytes=3,
        send_frame=send_frame,
    )

    manifest_sha256 = exporter.send_manifest()

    assert [frame.message_type for frame in sent] == [MessageType.MANIFEST]
    accepted = ManifestAccepted(
        analysis_id=ANALYSIS_ID,
        manifest_sha256=manifest_sha256,
        accepted_blob_count=2,
        accepted_total_bytes=11,
    )
    result = exporter.send_manifest_and_blobs(accepted, worker_duration_ms=123)

    assert [frame.message_type for frame in sent] == [
        MessageType.MANIFEST,
        MessageType.BLOB_BEGIN,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_END,
        MessageType.BLOB_BEGIN,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_END,
    ]
    first_begin = decode_json_message(sent[1].payload, BlobBegin)
    first_end = decode_json_message(sent[5].payload, BlobEnd)
    assert first_begin.blob_id == first_end.blob_id == "blob_00000000"
    assert first_begin.stream_id == 4096
    assert all(
        len(frame.payload) <= 3 for frame in sent if frame.message_type is MessageType.BLOB_CHUNK
    )
    assert all(frame.stream_id == 4096 for frame in sent[1:6])
    assert result == WorkerResult(
        analysis_id=ANALYSIS_ID,
        status="complete",
        adapter_id="archive/tar-v1",
        manifest_sha256=manifest_sha256,
        emitted_blob_count=2,
        emitted_total_bytes=11,
        warning_codes=[],
        worker_duration_ms=123,
    )


def test_changed_staged_blob_is_rejected_before_any_blob_frame(tmp_path: Path) -> None:
    request, staged, analyzed = _analyzed_tar(tmp_path)
    manifest = build_manifest(
        request=request,
        staged_input=staged,
        analysis=analyzed,
        worker_build_id=WORKER_BUILD_ID,
        generated_at_utc=GENERATED_AT,
    )
    sent: list[_SentFrame] = []
    exporter = WorkerExporter(
        manifest=manifest,
        output=analyzed,
        output_chunk_bytes=1024 * 1024,
        send_frame=lambda *args: sent.append(_SentFrame(*args)),
    )
    manifest_sha256 = exporter.send_manifest()
    analyzed.members[0].storage_path.write_bytes(b"changed")

    with pytest.raises(WorkerExportError) as exc_info:
        exporter.send_manifest_and_blobs(
            ManifestAccepted(
                analysis_id=ANALYSIS_ID,
                manifest_sha256=manifest_sha256,
                accepted_blob_count=2,
                accepted_total_bytes=11,
            ),
            worker_duration_ms=1,
        )

    assert exc_info.value.error_code == "WORKER_INTERNAL_ERROR"
    assert [frame.message_type for frame in sent] == [MessageType.MANIFEST]


def test_manifest_acceptance_must_match_before_any_blob_frame(tmp_path: Path) -> None:
    request, staged, analyzed = _analyzed_tar(tmp_path)
    manifest = build_manifest(
        request=request,
        staged_input=staged,
        analysis=analyzed,
        worker_build_id=WORKER_BUILD_ID,
        generated_at_utc=GENERATED_AT,
    )
    sent: list[_SentFrame] = []
    exporter = WorkerExporter(
        manifest=manifest,
        output=analyzed,
        output_chunk_bytes=1024 * 1024,
        send_frame=lambda *args: sent.append(_SentFrame(*args)),
    )
    manifest_sha256 = exporter.send_manifest()

    with pytest.raises(WorkerExportError) as exc_info:
        exporter.send_manifest_and_blobs(
            ManifestAccepted(
                analysis_id=ANALYSIS_ID,
                manifest_sha256=manifest_sha256,
                accepted_blob_count=1,
                accepted_total_bytes=11,
            ),
            worker_duration_ms=1,
        )

    assert exc_info.value.error_code == "WORKER_MANIFEST_NOT_ACCEPTED"
    assert [frame.message_type for frame in sent] == [MessageType.MANIFEST]


def _json_frame(
    message_type: MessageType,
    sequence: int,
    message: object,
    *,
    stream_id: int = 0,
) -> bytes:
    return FrameEncoder.encode(
        Frame(
            message_type=message_type,
            flags=FrameFlags.JSON_PAYLOAD,
            stream_id=stream_id,
            sequence=sequence,
            payload=encode_json_message(message),  # type: ignore[arg-type]
        )
    )


def _host_input_frames(input_bytes: bytes, request: AnalysisRequest) -> bytes:
    return b"".join(
        [
            _json_frame(
                MessageType.HELLO,
                0,
                Hello(
                    protocol_major=1,
                    protocol_minor=0,
                    session_id=SESSION_ID,
                    analysis_id=ANALYSIS_ID,
                    host_implementation="strix",
                    maximum_frame_payload=8 * 1024 * 1024,
                ),
            ),
            _json_frame(MessageType.ANALYSIS_REQUEST, 1, request),
            _json_frame(
                MessageType.INPUT_BEGIN,
                2,
                InputBegin(
                    analysis_id=ANALYSIS_ID,
                    input_artifact_id=INPUT_ID,
                    declared_size=len(input_bytes),
                    declared_sha256=hashlib.sha256(input_bytes).hexdigest(),
                ),
                stream_id=1,
            ),
            FrameEncoder.encode(
                Frame(
                    message_type=MessageType.INPUT_CHUNK,
                    stream_id=1,
                    sequence=3,
                    payload=input_bytes,
                )
            ),
            _json_frame(
                MessageType.INPUT_END,
                4,
                InputEnd(
                    analysis_id=ANALYSIS_ID,
                    actual_size=len(input_bytes),
                    actual_sha256=hashlib.sha256(input_bytes).hexdigest(),
                ),
                stream_id=1,
            ),
        ]
    )


def _decode_frames(raw: bytes) -> list[Frame]:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    return frames


class _AcceptingHost(io.BytesIO):
    def __init__(self, initial: bytes, writer: io.BytesIO) -> None:
        super().__init__(initial)
        self._writer = writer
        self._sent_acceptance = False

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        if data or self._sent_acceptance:
            return data
        manifest_frame = next(
            frame
            for frame in _decode_frames(self._writer.getvalue())
            if frame.message_type is MessageType.MANIFEST
        )
        manifest = decode_json_message(manifest_frame.payload, P2AManifest)
        self._sent_acceptance = True
        return _json_frame(
            MessageType.MANIFEST_ACCEPTED,
            5,
            ManifestAccepted(
                analysis_id=ANALYSIS_ID,
                manifest_sha256=hashlib.sha256(manifest_frame.payload).hexdigest(),
                accepted_blob_count=manifest.blob_count,
                accepted_total_bytes=manifest.total_blob_bytes,
            ),
        )


def test_worker_session_exports_valid_tar_only_after_manifest_acceptance(tmp_path: Path) -> None:
    source = build_tar(tmp_path / "source.tar", [TarFixtureEntry("config", b"value")])
    input_bytes = source.read_bytes()
    request = _request(input_bytes)
    writer = io.BytesIO()
    root = tmp_path / "session-work"
    root.mkdir()
    session = WorkerSession(
        staging=WorkerStaging(root),
        worker_build_id=WORKER_BUILD_ID,
        now=lambda: GENERATED_AT,
    )

    exit_code = session.run(
        _AcceptingHost(_host_input_frames(input_bytes, request), writer),
        writer,
    )

    assert exit_code == 0
    frames = _decode_frames(writer.getvalue())
    assert [frame.sequence for frame in frames] == list(range(len(frames)))
    assert [frame.message_type for frame in frames] == [
        MessageType.HELLO_ACK,
        MessageType.REQUEST_ACCEPTED,
        MessageType.INPUT_ACCEPTED,
        MessageType.MANIFEST,
        MessageType.BLOB_BEGIN,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_END,
        MessageType.RESULT,
    ]
    manifest = decode_json_message(frames[3].payload, P2AManifest)
    result = decode_json_message(frames[-1].payload, WorkerResult)
    assert manifest.status == result.status == "complete"
    assert manifest.blob_count == result.emitted_blob_count == 1
    assert frames[-1].flags == FrameFlags.JSON_PAYLOAD | FrameFlags.FINAL
