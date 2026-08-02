"""Recoverable SQLite metadata and content-addressed firmware blobs."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAnalysisRecord,
    FirmwareInputArtifact,
)


_MIGRATIONS = ((1, "0001_initial.sql"),)


class FirmwareRepository:
    """Own firmware metadata and blobs below one Product Security run."""

    def __init__(self, run_dir: Path) -> None:
        domain_root = run_dir if run_dir.name == "domain" else run_dir / "domain"
        self.root = domain_root / "firmware"
        self.database_path = self.root / "firmware.db"
        self.blob_root = self.root / "blobs" / "sha256"
        self.staging_root = self.root / "staging"

    def initialize(self) -> None:
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self._apply_migrations()
        self.recover()

    def new_staging_path(self) -> Path:
        self.staging_root.mkdir(parents=True, exist_ok=True)
        return self.staging_root / f"{uuid.uuid4().hex}.blob"

    def blob_path(self, sha256: str) -> Path:
        return self.blob_root / sha256[:2] / sha256

    def register_input(
        self,
        staged_path: Path,
        artifact: FirmwareInputArtifact,
    ) -> FirmwareInputArtifact:
        self._require_safe_staging_file(staged_path)
        actual_hash, actual_size = _hash_file(staged_path)
        if actual_hash != artifact.sha256 or actual_size != artifact.size_bytes:
            staged_path.unlink(missing_ok=True)
            raise FirmwareDomainError(
                "FIRMWARE_OUTPUT_HASH_MISMATCH",
                "Staged firmware bytes do not match their declared hash and size.",
                retryable=False,
            )

        existing = self._find_input(artifact.input_artifact_id)
        if existing is not None:
            staged_path.unlink(missing_ok=True)
            if existing.sha256 != artifact.sha256:
                raise FirmwareDomainError(
                    "FIRMWARE_ID_COLLISION",
                    "Firmware input ID resolves to different full SHA-256 values.",
                    retryable=False,
                )
            return existing

        commit_id = uuid.uuid4().hex
        target = self.blob_path(artifact.sha256)
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO commit_journal(
                    commit_id, input_artifact_id, artifact_json, staged_path,
                    blob_path, state, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'staging', ?)
                """,
                (
                    commit_id,
                    artifact.input_artifact_id,
                    artifact.model_dump_json(),
                    str(staged_path),
                    str(target),
                    now,
                ),
            )
        self._transition_commit(commit_id, "staging")
        self._promote_blob(staged_path, target, artifact)
        self._transition_commit(commit_id, "blobs_committed")
        self._commit_input_metadata(artifact)
        self._transition_commit(commit_id, "metadata_committed")
        self._transition_commit(commit_id, "complete")
        self._delete_commit(commit_id)
        return artifact

    def get_input(self, input_artifact_id: str) -> FirmwareInputArtifact:
        artifact = self._find_input(input_artifact_id)
        if artifact is None:
            raise FirmwareDomainError(
                "FIRMWARE_INPUT_NOT_FOUND",
                f"Firmware input '{input_artifact_id}' does not exist.",
                retryable=False,
            )
        return artifact

    def list_inputs(self, *, scan_id: str | None = None) -> list[FirmwareInputArtifact]:
        query = "SELECT * FROM firmware_input"
        parameters: tuple[str, ...] = ()
        if scan_id is not None:
            query += " WHERE scan_id = ?"
            parameters = (scan_id,)
        query += " ORDER BY created_at, input_artifact_id"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_input_from_row(row) for row in rows]

    def open_input_reader(self, input_artifact_id: str) -> BinaryIO:
        """Open and verify one immutable CAS input without exposing its path."""
        artifact = self.get_input(input_artifact_id)
        path = self.blob_path(artifact.sha256)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _corrupt_input_error(input_artifact_id) from exc

        reader = os.fdopen(descriptor, "rb")
        try:
            _verify_input_reader(reader, artifact)
        except BaseException:
            reader.close()
            raise
        reader.seek(0)
        return reader

    def create_analysis(self, record: FirmwareAnalysisRecord) -> FirmwareAnalysisRecord:
        existing = self._find_analysis(record.analysis_id)
        if existing is not None:
            if existing.input_artifact_id != record.input_artifact_id:
                raise FirmwareDomainError(
                    "FIRMWARE_ID_COLLISION",
                    "Firmware analysis ID refers to a different input.",
                    retryable=False,
                )
            return existing
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO firmware_analysis(
                    analysis_id, scan_id, input_artifact_id, status, resume_key,
                    limitations_json, created_at, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.analysis_id,
                    record.scan_id,
                    record.input_artifact_id,
                    record.status,
                    record.resume_key,
                    json.dumps(record.limitations),
                    record.created_at.isoformat(),
                    _iso_or_none(record.started_at),
                    _iso_or_none(record.completed_at),
                ),
            )
        return record

    def get_analysis(self, analysis_id: str) -> FirmwareAnalysisRecord:
        record = self._find_analysis(analysis_id)
        if record is None:
            raise FirmwareDomainError(
                "FIRMWARE_ANALYSIS_NOT_FOUND",
                f"Firmware analysis '{analysis_id}' does not exist.",
                retryable=False,
            )
        return record

    def transition_analysis(
        self,
        analysis_id: str,
        expected: set[str],
        target: str,
    ) -> None:
        """Atomically move an analysis when its current state is expected."""
        if not expected:
            raise ValueError("Expected analysis states must not be empty.")
        current = self.get_analysis(analysis_id)
        FirmwareAnalysisRecord.model_validate(
            {**current.model_dump(mode="python"), "status": target}
        )
        placeholders = ", ".join("?" for _ in expected)
        parameters = (target, analysis_id, *sorted(expected))
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE firmware_analysis
                SET status = ?
                WHERE analysis_id = ? AND status IN ({placeholders})
                """,  # noqa: S608 - placeholders are generated, values remain parameters.
                parameters,
            )
            if cursor.rowcount != 1:
                raise FirmwareDomainError(
                    "FIRMWARE_ANALYSIS_STATE_CONFLICT",
                    "Firmware analysis state changed before the requested transition.",
                    retryable=True,
                )

    def list_analyses(self, *, scan_id: str | None = None) -> list[FirmwareAnalysisRecord]:
        query = "SELECT * FROM firmware_analysis"
        parameters: tuple[str, ...] = ()
        if scan_id is not None:
            query += " WHERE scan_id = ?"
            parameters = (scan_id,)
        query += " ORDER BY created_at, analysis_id"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_analysis_from_row(row) for row in rows]

    def verify_blob(self, sha256: str) -> bool:
        path = self.blob_path(sha256)
        return path.is_file() and not path.is_symlink() and _hash_file(path)[0] == sha256

    def recover(self) -> None:
        with self._connect() as connection:
            commits = connection.execute(
                "SELECT * FROM commit_journal ORDER BY updated_at, commit_id"
            ).fetchall()
        for commit in commits:
            self._recover_commit(commit)

    def pending_commit_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM commit_journal").fetchone()
        return int(row[0])

    def applied_migrations(self) -> list[int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            ).fetchall()
        return [int(row[0]) for row in rows]

    def _apply_migrations(self) -> None:
        migration_root = Path(__file__).with_name("migrations")
        for _, filename in _MIGRATIONS:
            script = (migration_root / filename).read_text(encoding="utf-8")
            connection = self._connect()
            try:
                connection.executescript(script)
            finally:
                connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _find_input(self, input_artifact_id: str) -> FirmwareInputArtifact | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM firmware_input WHERE input_artifact_id = ?",
                (input_artifact_id,),
            ).fetchone()
        return None if row is None else _input_from_row(row)

    def _find_analysis(self, analysis_id: str) -> FirmwareAnalysisRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM firmware_analysis WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        return None if row is None else _analysis_from_row(row)

    def _require_safe_staging_file(self, staged_path: Path) -> None:
        try:
            staged_path.resolve(strict=True).relative_to(self.staging_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise FirmwareDomainError(
                "FIRMWARE_INVALID_STAGING_PATH",
                "Firmware staging path must remain inside the repository.",
                retryable=False,
            ) from exc
        if staged_path.is_symlink() or not staged_path.is_file():
            raise FirmwareDomainError(
                "FIRMWARE_INVALID_STAGING_PATH",
                "Firmware staging input must be a regular file.",
                retryable=False,
            )

    def _promote_blob(
        self,
        staged_path: Path,
        target: Path,
        artifact: FirmwareInputArtifact,
    ) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if not self.verify_blob(artifact.sha256):
                raise FirmwareDomainError(
                    "FIRMWARE_ARTIFACT_CORRUPT",
                    "Existing firmware blob does not match its content address.",
                    retryable=False,
                )
            staged_path.unlink(missing_ok=True)
            return
        staged_path.replace(target)
        _fsync_directory(target.parent)
        if not self.verify_blob(artifact.sha256):
            raise FirmwareDomainError(
                "FIRMWARE_ARTIFACT_CORRUPT",
                "Promoted firmware blob failed host hash verification.",
                retryable=False,
            )

    def _commit_input_metadata(self, artifact: FirmwareInputArtifact) -> None:
        geometry_json = (
            artifact.geometry_contract.model_dump_json()
            if artifact.geometry_contract is not None
            else None
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO blob(sha256, size_bytes, storage_name, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    artifact.sha256,
                    artifact.size_bytes,
                    artifact.storage_name,
                    artifact.created_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO firmware_input(
                    input_artifact_id, scan_id, project_id, sha256, size_bytes,
                    storage_name, label, source_type, source_description,
                    geometry_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.input_artifact_id,
                    artifact.scan_id,
                    artifact.project_id,
                    artifact.sha256,
                    artifact.size_bytes,
                    artifact.storage_name,
                    artifact.label,
                    artifact.source_type,
                    artifact.source_description,
                    geometry_json,
                    artifact.created_at.isoformat(),
                ),
            )

    def _transition_commit(self, commit_id: str, state: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE commit_journal SET state = ?, updated_at = ? WHERE commit_id = ?",
                (state, datetime.now(UTC).isoformat(), commit_id),
            )

    def _delete_commit(self, commit_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM commit_journal WHERE commit_id = ?", (commit_id,))

    def _recover_commit(self, commit: sqlite3.Row) -> None:
        try:
            artifact = FirmwareInputArtifact.model_validate_json(commit["artifact_json"])
        except ValueError as exc:
            raise FirmwareDomainError(
                "FIRMWARE_ARTIFACT_CORRUPT",
                "Firmware commit journal contains invalid metadata.",
                retryable=False,
            ) from exc
        staged_path = Path(commit["staged_path"])
        blob_path = Path(commit["blob_path"])
        state = str(commit["state"])
        commit_id = str(commit["commit_id"])

        if state == "staging":
            if staged_path.is_file() and not staged_path.is_symlink():
                actual_hash, actual_size = _hash_file(staged_path)
                if actual_hash != artifact.sha256 or actual_size != artifact.size_bytes:
                    raise self._corrupt_recovery_error()
                self._promote_blob(staged_path, blob_path, artifact)
            elif not self.verify_blob(artifact.sha256):
                raise self._corrupt_recovery_error()
            self._transition_commit(commit_id, "blobs_committed")
            state = "blobs_committed"

        if state == "blobs_committed":
            if not self.verify_blob(artifact.sha256):
                raise self._corrupt_recovery_error()
            self._commit_input_metadata(artifact)
            self._transition_commit(commit_id, "metadata_committed")
            state = "metadata_committed"

        if state == "metadata_committed":
            persisted = self._find_input(artifact.input_artifact_id)
            if persisted != artifact or not self.verify_blob(artifact.sha256):
                raise self._corrupt_recovery_error()
            self._transition_commit(commit_id, "complete")
            state = "complete"

        if state == "complete":
            staged_path.unlink(missing_ok=True)
            self._delete_commit(commit_id)

    @staticmethod
    def _corrupt_recovery_error() -> FirmwareDomainError:
        return FirmwareDomainError(
            "FIRMWARE_ARTIFACT_CORRUPT",
            "Interrupted firmware commit cannot be verified safely.",
            retryable=False,
        )


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _hash_reader(reader: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := reader.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _verify_input_reader(reader: BinaryIO, artifact: FirmwareInputArtifact) -> None:
    metadata = os.fstat(reader.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != artifact.size_bytes:
        raise _corrupt_input_error(artifact.input_artifact_id)
    actual_hash, actual_size = _hash_reader(reader)
    if actual_hash != artifact.sha256 or actual_size != artifact.size_bytes:
        raise _corrupt_input_error(artifact.input_artifact_id)


def _corrupt_input_error(input_artifact_id: str) -> FirmwareDomainError:
    return FirmwareDomainError(
        "FIRMWARE_ARTIFACT_CORRUPT",
        f"Firmware input '{input_artifact_id}' failed immutable CAS verification.",
        retryable=False,
    )


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _input_from_row(row: sqlite3.Row) -> FirmwareInputArtifact:
    geometry = json.loads(row["geometry_json"]) if row["geometry_json"] else None
    return FirmwareInputArtifact.model_validate(
        {
            "input_artifact_id": row["input_artifact_id"],
            "scan_id": row["scan_id"],
            "project_id": row["project_id"],
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
            "storage_name": row["storage_name"],
            "label": row["label"],
            "source_type": row["source_type"],
            "source_description": row["source_description"],
            "geometry_contract": geometry,
            "created_at": row["created_at"],
        }
    )


def _analysis_from_row(row: sqlite3.Row) -> FirmwareAnalysisRecord:
    return FirmwareAnalysisRecord.model_validate(
        {
            "analysis_id": row["analysis_id"],
            "scan_id": row["scan_id"],
            "input_artifact_id": row["input_artifact_id"],
            "status": row["status"],
            "resume_key": row["resume_key"],
            "limitations": json.loads(row["limitations_json"]),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
    )


def _iso_or_none(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()
