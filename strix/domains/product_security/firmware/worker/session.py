"""One-shot FWAP worker handshake, request, and input session."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, BinaryIO

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.constants import (
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.frame import (
    Frame,
    FrameDecoder,
    FrameEncoder,
    FrameSequenceValidator,
)
from strix.domains.product_security.firmware.protocol.messages import (
    AnalysisRequest,
    Cancel,
    Hello,
    HelloAck,
    InputAccepted,
    InputBegin,
    InputEnd,
    ManifestAccepted,
    RequestAccepted,
    decode_json_message,
    encode_json_message,
)
from strix.domains.product_security.firmware.protocol.state import (
    WorkerState,
    WorkerStateMachine,
)
from strix.domains.product_security.firmware.worker.adapters.base import AdapterOutput
from strix.domains.product_security.firmware.worker.export import WorkerExporter
from strix.domains.product_security.firmware.worker.limits import WorkerLimits
from strix.domains.product_security.firmware.worker.manifest import (
    LocalStatus,
    analyze_archive,
    build_manifest,
)
from strix.domains.product_security.firmware.worker.staging import (
    StagedInput,
    WorkerStaging,
    WorkerStagingError,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import BaseModel

    from strix.domains.product_security.firmware.protocol.messages import AdapterId


CONTROL_STREAM = 0
INPUT_STREAM = 1
READ_SIZE = 64 * 1024
SUPPORTED_ADAPTERS: list[AdapterId] = ["archive/tar-v1", "archive/zip-v1"]


class WorkerSessionError(FirmwareDomainError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(error_code, message, retryable=False)


class WorkerSession:
    def __init__(
        self,
        *,
        staging: WorkerStaging | None = None,
        worker_build_id: str,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._staging = staging or WorkerStaging()
        self._worker_build_id = worker_build_id
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic
        self._started = False
        self._state = WorkerStateMachine()
        self._incoming_sequence = FrameSequenceValidator()
        self._outgoing_sequence = 0
        self._hello: Hello | None = None
        self._request: AnalysisRequest | None = None
        self._limits: WorkerLimits | None = None
        self._staged: StagedInput | None = None
        self._analysis: AdapterOutput | LocalStatus | None = None
        self._exporter: WorkerExporter | None = None
        self._started_at = 0.0

    def run(self, reader: BinaryIO, writer: BinaryIO) -> int:
        if self._started:
            raise WorkerSessionError(
                "WORKER_INTERNAL_ERROR",
                "Worker session instances are one-shot.",
            )
        self._started = True
        self._started_at = self._monotonic()
        decoder = FrameDecoder()

        try:
            while True:
                data = reader.read(READ_SIZE)
                if not data:
                    decoder.finish()
                    break
                for frame in decoder.feed(data):
                    self._incoming_sequence.accept(frame)
                    self._accept(frame, writer)

        except WorkerStagingError as exc:
            self._staging.abort()
            raise WorkerSessionError(exc.error_code, exc.message) from exc
        except Exception:
            self._staging.abort()
            raise

        if self._state.state is not WorkerState.EXIT:
            self._staging.abort()
            raise FWAPProtocolError(
                "FWAP_UNEXPECTED_MESSAGE",
                f"FWAP input ended in state {self._state.state.value}.",
            )
        return 0

    def _accept(self, frame: Frame, writer: BinaryIO) -> None:
        if frame.message_type is MessageType.CANCEL:
            self._require_json_control(frame)
            cancel = decode_json_message(frame.payload, Cancel)
            if self._request is not None and cancel.analysis_id != self._request.analysis_id:
                self._fail_request("Cancel analysis identity does not match the request.")
            self._state.accept(MessageType.CANCEL)
            return

        if frame.message_type is MessageType.HELLO:
            self._accept_hello(frame, writer)
        elif frame.message_type is MessageType.ANALYSIS_REQUEST:
            self._accept_request(frame, writer)
        elif frame.message_type is MessageType.INPUT_BEGIN:
            self._accept_input_begin(frame)
        elif frame.message_type is MessageType.INPUT_CHUNK:
            self._accept_input_chunk(frame)
        elif frame.message_type is MessageType.INPUT_END:
            self._accept_input_end(frame, writer)
        elif frame.message_type is MessageType.MANIFEST_ACCEPTED:
            self._accept_manifest(frame, writer)
        else:
            self._state.accept(frame.message_type)

    def _accept_hello(self, frame: Frame, writer: BinaryIO) -> None:
        self._require_json_control(frame)
        hello = decode_json_message(frame.payload, Hello)
        self._state.accept(frame.message_type)
        self._hello = hello
        self._send(
            writer,
            MessageType.HELLO_ACK,
            HelloAck(
                protocol_major=1,
                protocol_minor=0,
                session_id=hello.session_id,
                worker_build_id=self._worker_build_id,
                worker_protocol="1.0",
                manifest_schema="p2a-manifest-1",
                supported_adapters=SUPPORTED_ADAPTERS,
                limits_profile="p2a-default-v1",
            ),
        )

    def _accept_request(self, frame: Frame, writer: BinaryIO) -> None:
        self._require_json_control(frame)
        request = decode_json_message(frame.payload, AnalysisRequest)
        self._state.accept(frame.message_type)
        hello = self._require_hello()
        if request.analysis_id != hello.analysis_id:
            self._fail_request("Request analysis identity does not match HELLO.")
        limits = WorkerLimits.from_analysis_limits(request.limits)
        if request.declared_input_size > limits.maximum_input_bytes:
            raise WorkerSessionError(
                "WORKER_LIMIT_INVALID",
                "Declared input exceeds the requested limit profile.",
            )
        if not set(request.enabled_adapters).issubset(SUPPORTED_ADAPTERS):
            self._fail_request("Request enables an unsupported adapter.")

        self._request = request
        self._limits = limits
        self._send(
            writer,
            MessageType.REQUEST_ACCEPTED,
            RequestAccepted(analysis_id=request.analysis_id),
        )

    def _accept_input_begin(self, frame: Frame) -> None:
        self._require_json_input(frame)
        begin = decode_json_message(frame.payload, InputBegin)
        self._state.accept(frame.message_type)
        request = self._require_request()
        limits = self._require_limits()
        if (
            begin.analysis_id != request.analysis_id
            or begin.input_artifact_id != request.input_artifact_id
            or begin.declared_size != request.declared_input_size
            or begin.declared_sha256 != request.declared_input_sha256
        ):
            self._fail_request("Input declaration does not match the accepted request.")
        self._staging.begin(
            declared_size=begin.declared_size,
            declared_sha256=begin.declared_sha256,
            maximum_input_bytes=limits.maximum_input_bytes,
            maximum_chunk_bytes=limits.input_chunk_bytes,
        )

    def _accept_input_chunk(self, frame: Frame) -> None:
        if frame.stream_id != INPUT_STREAM or frame.flags != FrameFlags.NONE:
            raise FWAPProtocolError(
                "FWAP_UNKNOWN_STREAM",
                "FWAP input chunks must use raw input stream 1.",
            )
        self._state.accept(frame.message_type)
        self._staging.write(frame.payload)

    def _accept_input_end(self, frame: Frame, writer: BinaryIO) -> None:
        self._require_json_input(frame)
        end = decode_json_message(frame.payload, InputEnd)
        self._state.accept(frame.message_type)
        request = self._require_request()
        if end.analysis_id != request.analysis_id:
            self._fail_request("Input end identity does not match the accepted request.")
        self._staged = self._staging.finish(
            actual_size=end.actual_size,
            actual_sha256=end.actual_sha256,
        )
        self._send(
            writer,
            MessageType.INPUT_ACCEPTED,
            InputAccepted(
                analysis_id=request.analysis_id,
                input_artifact_id=request.input_artifact_id,
                actual_size=self._staged.size,
                actual_sha256=self._staged.sha256,
            ),
        )
        self._state.advance(WorkerState.ANALYZE)
        self._analyze_and_send_manifest(writer)

    def _analyze_and_send_manifest(self, writer: BinaryIO) -> None:
        request = self._require_request()
        staged = self._require_staged()
        limits = self._require_limits()
        self._analysis = analyze_archive(
            input_path=staged.path,
            enabled_adapters=request.enabled_adapters,
            limits=limits,
            staging=self._staging,
        )
        manifest = build_manifest(
            request=request,
            staged_input=staged,
            analysis=self._analysis,
            worker_build_id=self._worker_build_id,
            generated_at_utc=self._now(),
        )
        output = self._analysis if isinstance(self._analysis, AdapterOutput) else None
        self._exporter = WorkerExporter(
            manifest=manifest,
            output=output,
            output_chunk_bytes=limits.output_chunk_bytes,
            maximum_manifest_bytes=limits.maximum_manifest_bytes,
            send_frame=lambda message_type, payload, stream_id, flags: self._send_frame_payload(
                writer,
                message_type,
                payload,
                stream_id=stream_id,
                flags=flags,
            ),
        )
        self._state.advance(WorkerState.WAIT_MANIFEST_ACCEPTANCE)
        self._exporter.send_manifest()

    def _accept_manifest(self, frame: Frame, writer: BinaryIO) -> None:
        self._require_json_control(frame)
        accepted = decode_json_message(frame.payload, ManifestAccepted)
        self._state.accept(frame.message_type)
        exporter = self._require_exporter()
        result = exporter.send_manifest_and_blobs(
            accepted,
            worker_duration_ms=max(
                0,
                int((self._monotonic() - self._started_at) * 1000),
            ),
        )
        self._state.advance(WorkerState.SEND_RESULT)
        self._send(
            writer,
            MessageType.RESULT,
            result,
            final=True,
        )
        self._state.advance(WorkerState.EXIT)

    def _send(
        self,
        writer: BinaryIO,
        message_type: MessageType,
        message: BaseModel,
        *,
        final: bool = False,
    ) -> None:
        self._send_payload(
            writer,
            message_type,
            encode_json_message(message),
            final=final,
        )

    def _send_payload(
        self,
        writer: BinaryIO,
        message_type: MessageType,
        payload: bytes,
        *,
        final: bool = False,
    ) -> None:
        flags = FrameFlags.JSON_PAYLOAD
        if final:
            flags |= FrameFlags.FINAL
        self._send_frame_payload(
            writer,
            message_type,
            payload,
            stream_id=CONTROL_STREAM,
            flags=flags,
        )

    def _send_frame_payload(
        self,
        writer: BinaryIO,
        message_type: MessageType,
        payload: bytes,
        *,
        stream_id: int,
        flags: FrameFlags,
    ) -> None:
        encoded = FrameEncoder.encode(
            Frame(
                message_type=message_type,
                flags=flags,
                stream_id=stream_id,
                sequence=self._outgoing_sequence,
                payload=payload,
            )
        )
        self._outgoing_sequence += 1
        if writer.write(encoded) != len(encoded):
            raise WorkerSessionError(
                "WORKER_INTERNAL_ERROR",
                "Worker protocol output write was incomplete.",
            )
        writer.flush()

    @staticmethod
    def _require_json_control(frame: Frame) -> None:
        if frame.stream_id != CONTROL_STREAM or frame.flags != FrameFlags.JSON_PAYLOAD:
            raise FWAPProtocolError(
                "FWAP_UNKNOWN_STREAM",
                "FWAP control messages must use JSON control stream 0.",
            )

    @staticmethod
    def _require_json_input(frame: Frame) -> None:
        if frame.stream_id != INPUT_STREAM or frame.flags != FrameFlags.JSON_PAYLOAD:
            raise FWAPProtocolError(
                "FWAP_UNKNOWN_STREAM",
                "FWAP input metadata must use JSON input stream 1.",
            )

    def _require_hello(self) -> Hello:
        if self._hello is None:
            raise WorkerSessionError("WORKER_INTERNAL_ERROR", "HELLO context is missing.")
        return self._hello

    def _require_request(self) -> AnalysisRequest:
        if self._request is None:
            raise WorkerSessionError("WORKER_INTERNAL_ERROR", "Request context is missing.")
        return self._request

    def _require_limits(self) -> WorkerLimits:
        if self._limits is None:
            raise WorkerSessionError("WORKER_INTERNAL_ERROR", "Worker limits are missing.")
        return self._limits

    def _require_staged(self) -> StagedInput:
        if self._staged is None:
            raise WorkerSessionError("WORKER_INTERNAL_ERROR", "Staged input is missing.")
        return self._staged

    def _require_exporter(self) -> WorkerExporter:
        if self._exporter is None:
            raise WorkerSessionError("WORKER_INTERNAL_ERROR", "Worker exporter is missing.")
        return self._exporter

    @staticmethod
    def _fail_request(message: str) -> None:
        raise WorkerSessionError("WORKER_REQUEST_INVALID", message)
