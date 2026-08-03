from __future__ import annotations

import ast
import hashlib
import io
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

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
    Hello,
    HelloAck,
    InputAccepted,
    InputBegin,
    InputEnd,
    ManifestAccepted,
    P2AManifest,
    RequestAccepted,
    WorkerResult,
    decode_json_message,
    encode_json_message,
)
from strix.domains.product_security.firmware.worker.limits import WorkerLimits
from strix.domains.product_security.firmware.worker.session import (
    WorkerSession,
    WorkerSessionError,
)
from strix.domains.product_security.firmware.worker.staging import WorkerStaging


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
SESSION_ID = "fwap_session_cccccccccccccccc"
WORKER_BUILD_ID = "d" * 64
INPUT = b"firmware-image"
INPUT_SHA256 = hashlib.sha256(INPUT).hexdigest()


def _limits() -> AnalysisLimits:
    return AnalysisLimits(
        maximum_input_bytes=512 * 1024 * 1024,
        maximum_output_bytes=1024 * 1024 * 1024,
        maximum_file_bytes=128 * 1024 * 1024,
        maximum_regular_files=20_000,
        maximum_manifest_bytes=8 * 1024 * 1024,
        input_chunk_bytes=1024 * 1024,
        output_chunk_bytes=1024 * 1024,
        analysis_timeout_seconds=180,
    )


def _hello() -> Hello:
    return Hello(
        protocol_major=1,
        protocol_minor=0,
        session_id=SESSION_ID,
        analysis_id=ANALYSIS_ID,
        host_implementation="strix",
        maximum_frame_payload=8 * 1024 * 1024,
    )


def _request(
    *,
    declared_size: int = len(INPUT),
    declared_sha256: str = INPUT_SHA256,
) -> AnalysisRequest:
    return AnalysisRequest(
        request_schema="p2a-request-1",
        analysis_id=ANALYSIS_ID,
        input_artifact_id=INPUT_ID,
        declared_input_size=declared_size,
        declared_input_sha256=declared_sha256,
        enabled_adapters=["archive/tar-v1", "archive/zip-v1"],
        limits=_limits(),
    )


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


def _input_frames(
    *,
    request: AnalysisRequest | None = None,
    chunk: bytes = INPUT,
    end_size: int | None = None,
    end_sha256: str | None = None,
) -> bytes:
    analysis_request = request or _request()
    begin = InputBegin(
        analysis_id=ANALYSIS_ID,
        input_artifact_id=INPUT_ID,
        declared_size=analysis_request.declared_input_size,
        declared_sha256=analysis_request.declared_input_sha256,
    )
    end = InputEnd(
        analysis_id=ANALYSIS_ID,
        actual_size=len(chunk) if end_size is None else end_size,
        actual_sha256=hashlib.sha256(chunk).hexdigest() if end_sha256 is None else end_sha256,
    )
    return b"".join(
        [
            _json_frame(MessageType.HELLO, 0, _hello()),
            _json_frame(MessageType.ANALYSIS_REQUEST, 1, analysis_request),
            _json_frame(MessageType.INPUT_BEGIN, 2, begin, stream_id=1),
            FrameEncoder.encode(
                Frame(
                    message_type=MessageType.INPUT_CHUNK,
                    stream_id=1,
                    sequence=3,
                    payload=chunk,
                )
            ),
            _json_frame(MessageType.INPUT_END, 4, end, stream_id=1),
        ]
    )


def _decode_frames(raw: bytes) -> list[Frame]:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    return frames


class _ManifestAcceptingReader(io.BytesIO):
    def __init__(self, initial: bytes, writer: io.BytesIO) -> None:
        super().__init__(initial)
        self._writer = writer
        self._acceptance_sent = False

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        if data or self._acceptance_sent:
            return data

        manifest_frame = next(
            frame
            for frame in _decode_frames(self._writer.getvalue())
            if frame.message_type is MessageType.MANIFEST
        )
        self._acceptance_sent = True
        return _json_frame(
            MessageType.MANIFEST_ACCEPTED,
            5,
            ManifestAccepted(
                analysis_id=ANALYSIS_ID,
                manifest_sha256=hashlib.sha256(manifest_frame.payload).hexdigest(),
                accepted_blob_count=0,
                accepted_total_bytes=0,
            ),
        )


def _session(tmp_path: Path) -> WorkerSession:
    return WorkerSession(
        staging=WorkerStaging(tmp_path),
        worker_build_id=WORKER_BUILD_ID,
        now=lambda: datetime(2026, 8, 3, tzinfo=UTC),
    )


def test_worker_limits_are_a_frozen_copy_of_request_limits() -> None:
    limits = WorkerLimits.from_analysis_limits(_limits())

    assert limits.model_dump() == _limits().model_dump()
    with pytest.raises(ValidationError):
        limits.maximum_input_bytes = 1  # type: ignore[misc]

    invalid = _limits().model_dump()
    invalid["maximum_input_bytes"] = 0
    with pytest.raises(ValidationError):
        WorkerLimits.model_validate(invalid)


def test_complete_handshake_request_and_input_session(tmp_path: Path) -> None:
    writer = io.BytesIO()
    reader = _ManifestAcceptingReader(_input_frames(), writer)

    exit_code = _session(tmp_path).run(reader, writer)

    assert exit_code == 0
    frames = _decode_frames(writer.getvalue())
    assert [frame.message_type for frame in frames] == [
        MessageType.HELLO_ACK,
        MessageType.REQUEST_ACCEPTED,
        MessageType.INPUT_ACCEPTED,
        MessageType.MANIFEST,
        MessageType.RESULT,
    ]
    assert [frame.sequence for frame in frames] == list(range(5))
    assert all(frame.stream_id == 0 for frame in frames)
    assert decode_json_message(frames[0].payload, HelloAck).session_id == SESSION_ID
    assert decode_json_message(frames[1].payload, RequestAccepted).analysis_id == ANALYSIS_ID

    accepted = decode_json_message(frames[2].payload, InputAccepted)
    assert accepted.actual_size == len(INPUT)
    assert accepted.actual_sha256 == INPUT_SHA256

    manifest = decode_json_message(frames[3].payload, P2AManifest)
    assert manifest.status == "not_applicable"
    assert manifest.adapter_id is None
    assert manifest.blob_count == 0
    result = decode_json_message(frames[4].payload, WorkerResult)
    assert result.status == "not_applicable"
    assert result.manifest_sha256 == hashlib.sha256(frames[3].payload).hexdigest()
    assert frames[4].flags == FrameFlags.JSON_PAYLOAD | FrameFlags.FINAL

    input_path = tmp_path / "input.bin"
    assert input_path.read_bytes() == INPUT
    assert stat.S_IMODE(input_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("analysis_request", "end_size", "end_sha256", "expected_code"),
    [
        (_request(declared_sha256="e" * 64), None, None, "WORKER_INPUT_HASH_MISMATCH"),
        (_request(), len(INPUT) - 1, None, "WORKER_INPUT_SIZE_MISMATCH"),
        (_request(), None, "e" * 64, "WORKER_INPUT_HASH_MISMATCH"),
    ],
)
def test_input_size_and_hash_mismatches_fail_before_input_acceptance(
    tmp_path: Path,
    analysis_request: AnalysisRequest,
    end_size: int | None,
    end_sha256: str | None,
    expected_code: str,
) -> None:
    writer = io.BytesIO()

    with pytest.raises(WorkerSessionError) as exc_info:
        _session(tmp_path).run(
            io.BytesIO(
                _input_frames(
                    request=analysis_request,
                    end_size=end_size,
                    end_sha256=end_sha256,
                )
            ),
            writer,
        )

    assert exc_info.value.error_code == expected_code
    assert MessageType.INPUT_ACCEPTED not in {
        frame.message_type for frame in _decode_frames(writer.getvalue())
    }
    assert not (tmp_path / "input.bin").exists()


def test_input_overrun_is_rejected_and_partial_file_is_removed(tmp_path: Path) -> None:
    writer = io.BytesIO()
    request = _request(declared_size=len(INPUT) - 1)

    with pytest.raises(WorkerSessionError) as exc_info:
        _session(tmp_path).run(
            io.BytesIO(_input_frames(request=request, chunk=INPUT)),
            writer,
        )

    assert exc_info.value.error_code == "WORKER_INPUT_TOO_LARGE"
    assert not (tmp_path / "input.bin").exists()


def test_existing_input_file_is_never_reused_or_overwritten(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"existing")
    writer = io.BytesIO()

    with pytest.raises(WorkerSessionError) as exc_info:
        _session(tmp_path).run(io.BytesIO(_input_frames()), writer)

    assert exc_info.value.error_code == "WORKER_INTERNAL_ERROR"
    assert input_path.read_bytes() == b"existing"
    assert MessageType.INPUT_ACCEPTED not in {
        frame.message_type for frame in _decode_frames(writer.getvalue())
    }


def test_worker_modules_do_not_write_unframed_stdout() -> None:
    worker_root = (
        Path(__file__).parents[5] / "strix" / "domains" / "product_security" / "firmware" / "worker"
    )
    modules = sorted(worker_root.glob("*.py"))

    assert modules
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
            for node in ast.walk(tree)
        ), f"print() is forbidden in worker module {module.name}"
