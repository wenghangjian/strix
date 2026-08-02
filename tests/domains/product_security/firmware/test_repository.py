from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import FirmwareInputArtifact
from strix.domains.product_security.firmware.repository import FirmwareRepository


if TYPE_CHECKING:
    from pathlib import Path


def _artifact(data: bytes, *, artifact_id: str | None = None) -> FirmwareInputArtifact:
    digest = hashlib.sha256(data).hexdigest()
    return FirmwareInputArtifact(
        input_artifact_id=artifact_id or f"fw_input_{digest[:16]}",
        scan_id="scan-1",
        sha256=digest,
        size_bytes=len(data),
        storage_name=digest,
        label="firmware.bin",
        source_type="fixture",
    )


def _staged(repo: FirmwareRepository, data: bytes) -> Path:
    path = repo.new_staging_path()
    path.write_bytes(data)
    return path


def test_repository_promotes_blob_and_metadata(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    data = b"firmware"

    artifact = repo.register_input(_staged(repo, data), _artifact(data))

    assert repo.get_input(artifact.input_artifact_id) == artifact
    assert repo.verify_blob(artifact.sha256) is True
    assert repo.blob_path(artifact.sha256).read_bytes() == data
    assert list(repo.staging_root.iterdir()) == []


def test_repository_initialization_and_registration_are_idempotent(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    repo.initialize()
    data = b"same-content"
    first = repo.register_input(_staged(repo, data), _artifact(data))
    second = repo.register_input(_staged(repo, data), _artifact(data))

    assert first == second
    assert repo.list_inputs(scan_id="scan-1") == [first]
    assert repo.applied_migrations() == [1]


def test_repository_rejects_hash_mismatch_without_metadata(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = _artifact(b"expected")

    with pytest.raises(FirmwareDomainError) as exc_info:
        repo.register_input(_staged(repo, b"different"), artifact)

    assert exc_info.value.error_code == "FIRMWARE_OUTPUT_HASH_MISMATCH"
    assert repo.list_inputs() == []


def test_repository_rejects_truncated_hash_id_collision(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    first_data = b"first"
    first = _artifact(first_data, artifact_id="fw_input_aaaaaaaaaaaaaaaa")
    repo.register_input(_staged(repo, first_data), first)
    second_data = b"second"
    second = _artifact(second_data, artifact_id=first.input_artifact_id)

    with pytest.raises(FirmwareDomainError) as exc_info:
        repo.register_input(_staged(repo, second_data), second)

    assert exc_info.value.error_code == "FIRMWARE_ID_COLLISION"


@pytest.mark.parametrize("crash_state", ["staging", "blobs_committed", "metadata_committed"])
def test_recovery_completes_valid_interrupted_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_state: str,
) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    data = f"firmware-{crash_state}".encode()
    artifact = _artifact(data)
    original = repo._transition_commit

    def crash_after_transition(commit_id: str, state: str) -> None:
        original(commit_id, state)
        if state == crash_state:
            raise RuntimeError("simulated process crash")

    monkeypatch.setattr(repo, "_transition_commit", crash_after_transition)

    with pytest.raises(RuntimeError, match="simulated process crash"):
        repo.register_input(_staged(repo, data), artifact)

    recovered = FirmwareRepository(tmp_path / "run")
    recovered.initialize()

    assert recovered.get_input(artifact.input_artifact_id) == artifact
    assert recovered.verify_blob(artifact.sha256) is True
    assert recovered.pending_commit_count() == 0


def test_recovery_rejects_corrupt_promoted_blob(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    data = b"firmware-corrupt"
    artifact = _artifact(data)
    original = repo._transition_commit

    def crash_after_blob(commit_id: str, state: str) -> None:
        original(commit_id, state)
        if state == "blobs_committed":
            raise RuntimeError("simulated process crash")

    repo._transition_commit = crash_after_blob  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        repo.register_input(_staged(repo, data), artifact)
    repo.blob_path(artifact.sha256).write_bytes(b"corrupt")

    with pytest.raises(FirmwareDomainError) as exc_info:
        FirmwareRepository(tmp_path / "run").initialize()

    assert exc_info.value.error_code == "FIRMWARE_ARTIFACT_CORRUPT"
