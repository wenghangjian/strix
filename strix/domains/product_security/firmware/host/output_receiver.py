"""Incremental FWAP blob receiver for untrusted firmware worker output."""

from __future__ import annotations

import hashlib
import os
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, Never, Protocol

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.constants import (
    UINT32_MAX,
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.frame import Frame, FrameDecoder
from strix.domains.product_security.firmware.protocol.messages import (
    BlobBegin,
    BlobEnd,
    P2AManifest,
    P2AManifestBlob,
    WorkerResult,
    decode_json_message,
)


if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from strix.domains.product_security.firmware.host.manifest_validator import (
        ManifestReservation,
    )
    from strix.domains.product_security.firmware.host.staging import HostStaging
    from strix.domains.product_security.firmware.runtime.worker_container import (
        ContainerObservation,
    )


@dataclass(frozen=True, slots=True)
class VerifiedStagingBlob:
    blob_id: str
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedWorkerOutput:
    manifest_bytes: bytes
    manifest: P2AManifest
    manifest_sha256: str
    staging_blobs: tuple[VerifiedStagingBlob, ...]
    result: WorkerResult
    container_observation: ContainerObservation | None = None


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...

    def hexdigest(self) -> str: ...


@dataclass(slots=True)
class _ActiveBlob:
    manifest: P2AManifestBlob
    path: Path
    writer: BinaryIO
    digest: _Digest
    size_bytes: int = 0


class HostOutputReceiver:
    def __init__(
        self,
        *,
        reservation: ManifestReservation,
        manifest_bytes: bytes,
        staging: HostStaging,
        starting_sequence: int,
    ) -> None:
        if starting_sequence < 0 or starting_sequence > UINT32_MAX:
            raise ValueError("starting_sequence is outside the FWAP range")
        if hashlib.sha256(manifest_bytes).hexdigest() != reservation.manifest_sha256:
            raise ValueError("manifest_bytes do not match the validated reservation")
        self._reservation = reservation
        self._manifest_bytes = manifest_bytes
        self._staging = staging
        self._expected_sequence = starting_sequence
        self._declared = {blob.blob_id: blob for blob in reservation.manifest.blobs}
        self._seen: set[str] = set()
        self._verified: list[VerifiedStagingBlob] = []
        self._active: _ActiveBlob | None = None
        self._result: WorkerResult | None = None

    def receive(self, chunks: Iterable[bytes]) -> VerifiedWorkerOutput:
        decoder = FrameDecoder()
        try:
            for chunk in chunks:
                if not chunk:
                    continue
                if self._result is not None:
                    _protocol("FWAP_TRAILING_OUTPUT", "FWAP output follows the final Result.")
                frames = decoder.feed(chunk)
                for frame in frames:
                    self._accept(frame)
            if self._result is not None and decoder.buffered_bytes:
                _protocol("FWAP_TRAILING_OUTPUT", "FWAP output follows the final Result.")
            decoder.finish()
            if self._active is not None:
                _reject("HOST_BLOB_SIZE_MISMATCH", "Worker exited before finishing a blob.")
            if self._result is None:
                _protocol("FWAP_RESULT_MISSING", "Worker output ended without a Result.")
            missing = self._reservation.blob_count - len(self._verified)
            if missing:
                _reject("HOST_BLOB_MISSING", "Worker Result omitted declared blobs.")
            return VerifiedWorkerOutput(
                manifest_bytes=self._manifest_bytes,
                manifest=self._reservation.manifest,
                manifest_sha256=self._reservation.manifest_sha256,
                staging_blobs=tuple(self._verified),
                result=self._result,
            )
        except BaseException:
            self._close_active()
            with suppress(FirmwareDomainError):
                self._staging.abort()
            raise

    def _accept(self, frame: Frame) -> None:
        if self._result is not None:
            _protocol("FWAP_TRAILING_OUTPUT", "FWAP output follows the final Result.")
        if frame.sequence != self._expected_sequence:
            _protocol(
                "FWAP_SEQUENCE_MISMATCH",
                f"FWAP sequence expected {self._expected_sequence}, received {frame.sequence}.",
            )
        self._expected_sequence += 1
        if frame.message_type is MessageType.BLOB_BEGIN:
            self._begin(frame)
        elif frame.message_type is MessageType.BLOB_CHUNK:
            self._write(frame)
        elif frame.message_type is MessageType.BLOB_END:
            self._end(frame)
        elif frame.message_type is MessageType.RESULT:
            self._accept_result(frame)
        else:
            _protocol("FWAP_UNEXPECTED_MESSAGE", "FWAP message is invalid during blob export.")

    def _begin(self, frame: Frame) -> None:
        _require_flags(frame, FrameFlags.JSON_PAYLOAD)
        if self._active is not None:
            _protocol("FWAP_UNEXPECTED_MESSAGE", "FWAP blob streams cannot interleave.")
        message = decode_json_message(frame.payload, BlobBegin)
        declared = self._declared.get(message.blob_id)
        if declared is None:
            _reject("HOST_BLOB_UNDECLARED", "Worker began an undeclared blob.")
        if message.blob_id in self._seen:
            _protocol("FWAP_DUPLICATE_BLOB", "Worker repeated a completed blob.")
        if frame.stream_id != declared.stream_id or message.stream_id != declared.stream_id:
            _protocol("FWAP_UNKNOWN_STREAM", "Worker used the wrong blob stream.")
        if (
            message.analysis_id != self._reservation.manifest.analysis_id
            or message.declared_size != declared.size_bytes
            or message.declared_sha256 != declared.sha256
        ):
            _reject("HOST_BLOB_UNDECLARED", "Worker blob declaration differs from the manifest.")
        path, writer = self._staging.create_blob(declared.generated_storage_name)
        self._active = _ActiveBlob(
            manifest=declared,
            path=path,
            writer=writer,
            digest=hashlib.sha256(),
        )

    def _write(self, frame: Frame) -> None:
        _require_flags(frame, FrameFlags.NONE)
        active = self._require_active()
        if frame.stream_id != active.manifest.stream_id:
            _protocol("FWAP_UNKNOWN_STREAM", "Worker used the wrong blob stream.")
        next_size = active.size_bytes + len(frame.payload)
        if next_size > active.manifest.size_bytes:
            _reject("HOST_BLOB_SIZE_MISMATCH", "Worker blob exceeds its declared size.")
        written = active.writer.write(frame.payload)
        if written != len(frame.payload):
            _reject("HOST_BLOB_SIZE_MISMATCH", "Host blob staging write was incomplete.")
        active.digest.update(frame.payload)
        active.size_bytes = next_size

    def _end(self, frame: Frame) -> None:
        _require_flags(frame, FrameFlags.JSON_PAYLOAD)
        active = self._require_active()
        if frame.stream_id != active.manifest.stream_id:
            _protocol("FWAP_UNKNOWN_STREAM", "Worker used the wrong blob stream.")
        message = decode_json_message(frame.payload, BlobEnd)
        active.writer.flush()
        os.fsync(active.writer.fileno())
        active.writer.close()
        actual_sha256 = active.digest.hexdigest()
        if message.blob_id != active.manifest.blob_id:
            _reject("HOST_BLOB_UNDECLARED", "Worker ended a different blob.")
        if message.analysis_id != self._reservation.manifest.analysis_id:
            _reject("HOST_BLOB_UNDECLARED", "Worker blob identity differs from the manifest.")
        if (
            message.actual_size != active.size_bytes
            or active.size_bytes != active.manifest.size_bytes
        ):
            _reject("HOST_BLOB_SIZE_MISMATCH", "Worker blob size does not match its manifest.")
        if message.actual_sha256 != actual_sha256 or actual_sha256 != active.manifest.sha256:
            _reject("HOST_BLOB_HASH_MISMATCH", "Worker blob hash does not match its manifest.")
        self._seen.add(active.manifest.blob_id)
        self._verified.append(
            VerifiedStagingBlob(
                blob_id=active.manifest.blob_id,
                path=active.path,
                size_bytes=active.size_bytes,
                sha256=actual_sha256,
            )
        )
        self._active = None

    def _accept_result(self, frame: Frame) -> None:
        _require_flags(frame, FrameFlags.JSON_PAYLOAD | FrameFlags.FINAL)
        if frame.stream_id != 0:
            _protocol("FWAP_UNKNOWN_STREAM", "Worker Result must use the control stream.")
        if self._active is not None:
            _reject("HOST_BLOB_SIZE_MISMATCH", "Worker Result interrupted an active blob.")
        if len(self._verified) != self._reservation.blob_count:
            _reject("HOST_BLOB_MISSING", "Worker Result omitted declared blobs.")
        result = decode_json_message(frame.payload, WorkerResult)
        manifest = self._reservation.manifest
        if (
            result.analysis_id != manifest.analysis_id
            or result.status != manifest.status
            or result.adapter_id != manifest.adapter_id
            or result.manifest_sha256 != self._reservation.manifest_sha256
            or result.emitted_blob_count != self._reservation.blob_count
            or result.emitted_total_bytes != self._reservation.total_bytes
            or result.warning_codes != manifest.warning_codes
        ):
            _reject("HOST_RESULT_MISMATCH", "Worker Result does not match its manifest.")
        self._result = result

    def _require_active(self) -> _ActiveBlob:
        if self._active is None:
            _protocol("FWAP_UNEXPECTED_MESSAGE", "FWAP blob data has no active declaration.")
        return self._active

    def _close_active(self) -> None:
        if self._active is None:
            return
        if not self._active.writer.closed:
            self._active.writer.close()
        self._active = None


def _require_flags(frame: Frame, expected: FrameFlags) -> None:
    if frame.flags != expected:
        _protocol("FWAP_BAD_FLAGS", "FWAP frame flags are invalid for this message.")


def _reject(error_code: str, message: str) -> Never:
    raise FirmwareDomainError(error_code, message, retryable=False)


def _protocol(error_code: str, message: str) -> Never:
    raise FWAPProtocolError(error_code, message)
