"""Private generated staging for Host-verified firmware worker blobs."""

from __future__ import annotations

import os
import re
import shutil
import stat
import uuid
from typing import TYPE_CHECKING, BinaryIO

from strix.domains.product_security.firmware.errors import FirmwareDomainError


if TYPE_CHECKING:
    from pathlib import Path


_ANALYSIS_ID = re.compile(r"^fw_analysis_[0-9a-f]{16,64}$")
_BLOB_NAME = re.compile(r"^blob_[0-9]{8}$")


class HostStaging:
    def __init__(self, root: Path, analysis_id: str) -> None:
        if _ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise ValueError("analysis_id does not match the firmware identity contract")
        self._root = root
        self._analysis_root = root / analysis_id
        self.run_root = self._analysis_root / uuid.uuid4().hex
        try:
            _ensure_private_directory(self._root)
            _ensure_private_directory(self._analysis_root)
            self.run_root.mkdir(mode=0o700)
            self.run_root.chmod(0o700)
        except OSError as exc:
            raise FirmwareDomainError(
                "HOST_STAGING_CREATE_FAILED",
                "Host output staging could not be created.",
                retryable=False,
            ) from exc

    def create_blob(self, generated_name: str) -> tuple[Path, BinaryIO]:
        if _BLOB_NAME.fullmatch(generated_name) is None:
            raise FirmwareDomainError(
                "HOST_MANIFEST_SCHEMA_INVALID",
                "Host staging requires a generated blob name.",
                retryable=False,
            )
        path = self.run_root / generated_name
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            return path, os.fdopen(descriptor, "wb")
        except OSError as exc:
            raise FirmwareDomainError(
                "HOST_STAGING_CREATE_FAILED",
                "Host blob staging file could not be created.",
                retryable=False,
            ) from exc

    def abort(self) -> None:
        try:
            shutil.rmtree(self.run_root)
            self._analysis_root.rmdir()
        except FileNotFoundError:
            return
        except OSError as exc:
            if self.run_root.exists():
                raise FirmwareDomainError(
                    "HOST_STAGING_CLEANUP_FAILED",
                    "Host output staging could not be removed.",
                    retryable=False,
                ) from exc


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError("Host staging path is not a directory")
    path.chmod(0o700)
