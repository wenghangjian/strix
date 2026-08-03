"""Manifest-gated FWAP blob export from generated worker staging files."""

from __future__ import annotations

import hashlib
import os
import stat
from typing import TYPE_CHECKING, Never, Protocol

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.constants import (
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.messages import (
    BlobBegin,
    BlobEnd,
    ManifestAccepted,
    P2AManifest,
    P2AManifestBlob,
    WorkerResult,
    encode_json_message,
)


if TYPE_CHECKING:
    from pathlib import Path

    from strix.domains.product_security.firmware.worker.adapters.base import AdapterOutput


class FrameSender(Protocol):
    def __call__(
        self,
        message_type: MessageType,
        payload: bytes,
        stream_id: int,
        flags: FrameFlags,
    ) -> None: ...


class WorkerExportError(FirmwareDomainError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(error_code, message, retryable=False)


class WorkerExporter:
    def __init__(
        self,
        *,
        manifest: P2AManifest,
        output: AdapterOutput | None,
        output_chunk_bytes: int,
        send_frame: FrameSender,
        maximum_manifest_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self._manifest = manifest
        self._output = output
        self._output_chunk_bytes = output_chunk_bytes
        self._send_frame = send_frame
        self._maximum_manifest_bytes = maximum_manifest_bytes
        self._manifest_sha256: str | None = None
        self._exported = False
        self._validate_contract()

    def send_manifest(self) -> str:
        if self._manifest_sha256 is not None:
            self._fail("WORKER_INTERNAL_ERROR", "Worker manifest was already sent.")
        payload = encode_json_message(self._manifest)
        if len(payload) > self._maximum_manifest_bytes:
            self._fail("WORKER_MANIFEST_TOO_LARGE", "Worker manifest exceeds its limit.")
        self._manifest_sha256 = hashlib.sha256(payload).hexdigest()
        self._send_frame(
            MessageType.MANIFEST,
            payload,
            0,
            FrameFlags.JSON_PAYLOAD,
        )
        return self._manifest_sha256

    def send_manifest_and_blobs(
        self,
        accepted: ManifestAccepted,
        *,
        worker_duration_ms: int,
    ) -> WorkerResult:
        manifest_sha256 = self._require_manifest_sha256()
        if self._exported:
            self._fail("WORKER_INTERNAL_ERROR", "Worker blobs were already exported.")
        if (
            accepted.analysis_id != self._manifest.analysis_id
            or accepted.manifest_sha256 != manifest_sha256
            or accepted.accepted_blob_count != self._manifest.blob_count
            or accepted.accepted_total_bytes != self._manifest.total_blob_bytes
        ):
            self._fail(
                "WORKER_MANIFEST_NOT_ACCEPTED",
                "Host manifest acceptance does not match worker output.",
            )
        self._verify_all_staged_blobs()

        emitted_count = 0
        emitted_bytes = 0
        if self._output is not None:
            for blob, extracted in zip(
                self._manifest.blobs,
                self._output.members,
                strict=True,
            ):
                actual_size, _ = self._send_blob(blob, extracted.storage_path)
                emitted_count += 1
                emitted_bytes += actual_size
        if (
            emitted_count != self._manifest.blob_count
            or emitted_bytes != self._manifest.total_blob_bytes
        ):
            self._fail("WORKER_INTERNAL_ERROR", "Emitted blobs do not match the manifest.")
        self._exported = True
        return WorkerResult(
            analysis_id=self._manifest.analysis_id,
            status=self._manifest.status,
            adapter_id=self._manifest.adapter_id,
            manifest_sha256=manifest_sha256,
            emitted_blob_count=emitted_count,
            emitted_total_bytes=emitted_bytes,
            warning_codes=self._manifest.warning_codes,
            worker_duration_ms=worker_duration_ms,
        )

    def _send_blob(self, blob: P2AManifestBlob, path: Path) -> tuple[int, str]:
        self._send_frame(
            MessageType.BLOB_BEGIN,
            encode_json_message(
                BlobBegin(
                    analysis_id=self._manifest.analysis_id,
                    blob_id=blob.blob_id,
                    stream_id=blob.stream_id,
                    declared_size=blob.size_bytes,
                    declared_sha256=blob.sha256,
                )
            ),
            blob.stream_id,
            FrameFlags.JSON_PAYLOAD,
        )
        actual_size = 0
        digest = hashlib.sha256()
        with path.open("rb") as source:
            initial = source.fileno()
            initial_size = _regular_file_size(initial)
            if initial_size != blob.size_bytes:
                self._fail("WORKER_INTERNAL_ERROR", "Staged blob size changed before export.")
            while chunk := source.read(self._output_chunk_bytes):
                actual_size += len(chunk)
                if actual_size > blob.size_bytes:
                    self._fail("WORKER_INTERNAL_ERROR", "Staged blob grew during export.")
                digest.update(chunk)
                self._send_frame(
                    MessageType.BLOB_CHUNK,
                    chunk,
                    blob.stream_id,
                    FrameFlags.NONE,
                )
            if _regular_file_size(initial) != initial_size or actual_size != blob.size_bytes:
                self._fail("WORKER_INTERNAL_ERROR", "Staged blob size changed during export.")
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != blob.sha256:
            self._fail("WORKER_INTERNAL_ERROR", "Staged blob identity changed during export.")
        self._send_frame(
            MessageType.BLOB_END,
            encode_json_message(
                BlobEnd(
                    analysis_id=self._manifest.analysis_id,
                    blob_id=blob.blob_id,
                    actual_size=actual_size,
                    actual_sha256=actual_sha256,
                )
            ),
            blob.stream_id,
            FrameFlags.JSON_PAYLOAD,
        )
        return actual_size, actual_sha256

    def _verify_all_staged_blobs(self) -> None:
        if self._output is None:
            return
        for blob, extracted in zip(
            self._manifest.blobs,
            self._output.members,
            strict=True,
        ):
            try:
                if extracted.storage_path.name != blob.generated_storage_name:
                    self._fail("WORKER_INTERNAL_ERROR", "Staged blob name is not generated.")
                metadata = extracted.storage_path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != blob.size_bytes:
                    self._fail("WORKER_INTERNAL_ERROR", "Staged blob metadata changed.")
                digest = hashlib.sha256()
                with extracted.storage_path.open("rb") as source:
                    while chunk := source.read(self._output_chunk_bytes):
                        digest.update(chunk)
                if digest.hexdigest() != blob.sha256:
                    self._fail("WORKER_INTERNAL_ERROR", "Staged blob identity changed.")
            except OSError as exc:
                raise WorkerExportError(
                    "WORKER_INTERNAL_ERROR",
                    "Staged blob could not be verified.",
                ) from exc

    def _validate_contract(self) -> None:
        if self._output_chunk_bytes <= 0 or self._output_chunk_bytes > 1024 * 1024:
            self._fail("WORKER_LIMIT_INVALID", "Worker output chunk limit is invalid.")
        if self._output is None:
            if self._manifest.blobs:
                self._fail("WORKER_INTERNAL_ERROR", "Manifest blobs have no staged output.")
            return
        if (
            self._output.adapter_id != self._manifest.adapter_id
            or len(self._output.members) != self._manifest.blob_count
            or self._output.total_bytes != self._manifest.total_blob_bytes
        ):
            self._fail("WORKER_INTERNAL_ERROR", "Manifest does not match staged output.")

    def _require_manifest_sha256(self) -> str:
        if self._manifest_sha256 is None:
            self._fail("WORKER_INTERNAL_ERROR", "Worker manifest was not sent.")
        return self._manifest_sha256

    @staticmethod
    def _fail(error_code: str, message: str) -> Never:
        raise WorkerExportError(error_code, message)


def _regular_file_size(descriptor: int) -> int:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise WorkerExportError("WORKER_INTERNAL_ERROR", "Staged blob is not a regular file.")
    return metadata.st_size
