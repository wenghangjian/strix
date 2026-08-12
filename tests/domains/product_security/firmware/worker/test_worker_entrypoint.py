from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

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
    WorkerError,
    decode_json_message,
    encode_json_message,
)


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
OTHER_ANALYSIS_ID = "fw_analysis_eeeeeeeeeeeeeeee"
SESSION_ID = "fwap_session_cccccccccccccccc"
WORKER_BUILD_ID = "d" * 64
REPOSITORY_ROOT = Path(__file__).parents[5]
ENTRYPOINT = (
    REPOSITORY_ROOT
    / "strix"
    / "domains"
    / "product_security"
    / "firmware"
    / "worker"
    / "__main__.py"
)


def _json_frame(message_type: MessageType, sequence: int, message: object) -> bytes:
    return FrameEncoder.encode(
        Frame(
            message_type=message_type,
            flags=FrameFlags.JSON_PAYLOAD,
            stream_id=0,
            sequence=sequence,
            payload=encode_json_message(message),  # type: ignore[arg-type]
        )
    )


def _hello_then_invalid_request() -> bytes:
    hello = Hello(
        protocol_major=1,
        protocol_minor=0,
        session_id=SESSION_ID,
        analysis_id=ANALYSIS_ID,
        host_implementation="strix-entrypoint-test",
        maximum_frame_payload=8 * 1024 * 1024,
    )
    request = AnalysisRequest(
        request_schema="p2a-request-1",
        analysis_id=OTHER_ANALYSIS_ID,
        input_artifact_id="fw_input_bbbbbbbbbbbbbbbb",
        declared_input_size=4,
        declared_input_sha256="e" * 64,
        enabled_adapters=["archive/tar-v1"],
        limits=AnalysisLimits(
            maximum_input_bytes=512 * 1024 * 1024,
            maximum_output_bytes=1024 * 1024 * 1024,
            maximum_file_bytes=128 * 1024 * 1024,
            maximum_regular_files=20_000,
            maximum_manifest_bytes=8 * 1024 * 1024,
            input_chunk_bytes=1024 * 1024,
            output_chunk_bytes=1024 * 1024,
            analysis_timeout_seconds=180,
        ),
    )
    return _json_frame(MessageType.HELLO, 0, hello) + _json_frame(
        MessageType.ANALYSIS_REQUEST,
        1,
        request,
    )


def _decode_frames(raw: bytes) -> list[Frame]:
    decoder = FrameDecoder()
    frames = decoder.feed(raw)
    decoder.finish()
    return frames


def test_local_worker_subprocess_emits_only_fwap_and_maps_expected_error() -> None:
    environment = {
        **os.environ,
        "STRIX_FIRMWARE_WORKER_BUILD_ID": WORKER_BUILD_ID,
        "PYTHONUNBUFFERED": "1",
    }

    completed = subprocess.run(
        [sys.executable, "-m", "strix.domains.product_security.firmware.worker"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        input=_hello_then_invalid_request(),
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 2
    assert completed.stderr == b""
    frames = _decode_frames(completed.stdout)
    assert [frame.message_type for frame in frames] == [
        MessageType.HELLO_ACK,
        MessageType.ERROR,
    ]
    assert [frame.sequence for frame in frames] == [0, 1]
    hello_ack = decode_json_message(frames[0].payload, HelloAck)
    assert hello_ack.worker_build_id == WORKER_BUILD_ID
    error = decode_json_message(frames[1].payload, WorkerError)
    assert error.analysis_id == ANALYSIS_ID
    assert error.error_code == "WORKER_REQUEST_INVALID"
    assert error.phase == "protocol"
    assert not error.retryable
    assert len(error.message) <= 512
    assert frames[1].flags == FrameFlags.JSON_PAYLOAD | FrameFlags.FINAL


def test_entrypoint_uses_fixed_binary_streams_without_logging_or_print() -> None:
    source = ENTRYPOINT.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(ENTRYPOINT))

    assert "sys.stdin.buffer" in source
    assert "sys.stdout.buffer" in source
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(alias.name == "logging" for alias in node.names)
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"
        for node in ast.walk(tree)
    )


def test_worker_image_copies_entrypoint_and_embeds_source_digest() -> None:
    dockerfile = (REPOSITORY_ROOT / "docker" / "firmware-worker" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "COPY strix/domains/product_security/firmware/worker" in dockerfile
    assert "STRIX_FIRMWARE_WORKER_BUILD_ID=${WORKER_SOURCE_DIGEST}" in dockerfile
