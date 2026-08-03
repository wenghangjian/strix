"""Bounded worker-side staging for the immutable firmware input."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from strix.domains.product_security.firmware.errors import FirmwareDomainError


@dataclass(frozen=True, slots=True)
class StagedInput:
    path: Path
    size: int
    sha256: str


class WorkerStagingError(FirmwareDomainError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(error_code, message, retryable=False)


class WorkerStaging:
    def __init__(self, root: Path = Path("/work")) -> None:
        self.root = root
        self.input_path = root / "input.bin"
        self._file: BinaryIO | None = None
        self._created = False
        self._declared_size = 0
        self._declared_sha256 = ""
        self._maximum_input_bytes = 0
        self._maximum_chunk_bytes = 0
        self._received_size = 0
        self._hasher = hashlib.sha256()

    def begin(
        self,
        *,
        declared_size: int,
        declared_sha256: str,
        maximum_input_bytes: int,
        maximum_chunk_bytes: int,
    ) -> None:
        if self._file is not None or self._created:
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Input staging has already started.",
            )
        if declared_size > maximum_input_bytes:
            raise WorkerStagingError(
                "WORKER_INPUT_TOO_LARGE",
                "Declared input exceeds the requested worker limit.",
            )
        if not self.root.is_dir():
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Worker staging directory is unavailable.",
            )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.input_path, flags, 0o600)
        except FileExistsError as exc:
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Worker input staging path already exists.",
            ) from exc
        except OSError as exc:
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Worker input staging could not be created.",
            ) from exc

        self._file = os.fdopen(descriptor, "wb", buffering=0)
        self._created = True
        self._declared_size = declared_size
        self._declared_sha256 = declared_sha256
        self._maximum_input_bytes = maximum_input_bytes
        self._maximum_chunk_bytes = maximum_chunk_bytes

    def write(self, chunk: bytes) -> None:
        if self._file is None:
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Input staging has not started.",
            )
        next_size = self._received_size + len(chunk)
        if len(chunk) > self._maximum_chunk_bytes:
            self.abort()
            raise WorkerStagingError(
                "WORKER_INPUT_TOO_LARGE",
                "Input chunk exceeds the requested worker limit.",
            )
        if next_size > min(self._declared_size, self._maximum_input_bytes):
            self.abort()
            raise WorkerStagingError(
                "WORKER_INPUT_TOO_LARGE",
                "Received input exceeds its declared size or worker limit.",
            )

        written = self._file.write(chunk)
        if written != len(chunk):
            self.abort()
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Worker input staging write was incomplete.",
            )
        self._received_size = next_size
        self._hasher.update(chunk)

    def finish(self, *, actual_size: int, actual_sha256: str) -> StagedInput:
        if self._file is None:
            raise WorkerStagingError(
                "WORKER_INTERNAL_ERROR",
                "Input staging has not started.",
            )
        self._close_file()
        received_sha256 = self._hasher.hexdigest()

        if actual_size != self._received_size or self._received_size != self._declared_size:
            self.abort()
            raise WorkerStagingError(
                "WORKER_INPUT_SIZE_MISMATCH",
                "Received input did not match the declared size.",
            )
        if actual_sha256 != received_sha256 or received_sha256 != self._declared_sha256:
            self.abort()
            raise WorkerStagingError(
                "WORKER_INPUT_HASH_MISMATCH",
                "Received input did not match the declared identity.",
            )
        return StagedInput(
            path=self.input_path,
            size=self._received_size,
            sha256=received_sha256,
        )

    def abort(self) -> None:
        self._close_file()
        if self._created:
            try:
                self.input_path.unlink(missing_ok=True)
            finally:
                self._created = False

    def _close_file(self) -> None:
        if self._file is None:
            return
        try:
            self._file.flush()
            os.fsync(self._file.fileno())
        finally:
            self._file.close()
            self._file = None
