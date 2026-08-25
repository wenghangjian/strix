from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.host.output_receiver import (
    VerifiedStagingBlob,
    VerifiedWorkerOutput,
)
from strix.domains.product_security.firmware.host.verifier import (
    verify_worker_completion,
)
from strix.domains.product_security.firmware.protocol.messages import (
    ArchiveMemberMetadata,
    ArchivePathMetadata,
    P2AManifest,
    P2AManifestBlob,
    WorkerResult,
    encode_json_message,
)
from strix.domains.product_security.firmware.runtime.worker_container import (
    ContainerObservation,
)


if TYPE_CHECKING:
    from pathlib import Path


ANALYSIS_ID = "fw_analysis_aaaaaaaaaaaaaaaa"
INPUT_ID = "fw_input_bbbbbbbbbbbbbbbb"
INPUT_SHA256 = "c" * 64
BLOB_BYTES = b"verified-firmware"
BLOB_SHA256 = hashlib.sha256(BLOB_BYTES).hexdigest()


def _output(tmp_path: Path) -> VerifiedWorkerOutput:
    blob_path = tmp_path / "blob_00000000"
    blob_path.write_bytes(BLOB_BYTES)
    blob = P2AManifestBlob(
        blob_id="blob_00000000",
        stream_id=4096,
        ordinal=0,
        generated_storage_name="blob_00000000",
        size_bytes=len(BLOB_BYTES),
        sha256=BLOB_SHA256,
        relation="extracted",
        parent_input_artifact_id=INPUT_ID,
        path=ArchivePathMetadata(
            display_path="etc/config",
            canonical_path="etc/config",
            raw_name_b64=None,
            path_encoding=None,
        ),
        archive=ArchiveMemberMetadata(
            member_index=0,
            member_type="regular_file",
            declared_size=len(BLOB_BYTES),
            actual_size=len(BLOB_BYTES),
            compression_method="stored",
            crc32=None,
            unix_mode=0o600,
            uid=None,
            gid=None,
            mtime_utc=None,
        ),
    )
    manifest = P2AManifest(
        manifest_schema="p2a-manifest-1",
        protocol_version="1.0",
        analysis_id=ANALYSIS_ID,
        input_artifact_id=INPUT_ID,
        input_size=10,
        input_sha256=INPUT_SHA256,
        adapter_id="archive/tar-v1",
        adapter_version="1.0",
        status="complete",
        generated_at_utc=datetime(2026, 8, 25, tzinfo=UTC),
        worker_build_id="e" * 64,
        blob_count=1,
        total_blob_bytes=len(BLOB_BYTES),
        blobs=[blob],
        warning_codes=[],
        rejected_entry_count=0,
        ignored_directory_count=0,
        limits_profile="p2a-default-v1",
    )
    manifest_bytes = encode_json_message(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    result = WorkerResult(
        analysis_id=ANALYSIS_ID,
        status="complete",
        adapter_id="archive/tar-v1",
        manifest_sha256=manifest_sha256,
        emitted_blob_count=1,
        emitted_total_bytes=len(BLOB_BYTES),
        warning_codes=[],
        worker_duration_ms=25,
    )
    return VerifiedWorkerOutput(
        manifest_bytes=manifest_bytes,
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        staging_blobs=(
            VerifiedStagingBlob(
                blob_id=blob.blob_id,
                path=blob_path,
                size_bytes=blob.size_bytes,
                sha256=blob.sha256,
            ),
        ),
        result=result,
    )


def _observation(
    *,
    exit_code: int | None = 0,
    running: bool = False,
    oom_killed: bool = False,
) -> ContainerObservation:
    return ContainerObservation(
        container_id="container-123",
        status="exited" if not running else "running",
        running=running,
        exit_code=exit_code,
        oom_killed=oom_killed,
        error=None,
        removed=True,
        cleanup_errors=(),
    )


def _assert_rejected(
    output: VerifiedWorkerOutput,
    observation: ContainerObservation,
    error_code: str,
) -> None:
    with pytest.raises(FirmwareDomainError) as raised:
        verify_worker_completion(output, observation)
    assert raised.value.error_code == error_code
    assert not raised.value.retryable


def test_zero_exit_with_complete_protocol_attaches_container_observation(tmp_path: Path) -> None:
    output = _output(tmp_path)
    observation = _observation()

    verified = verify_worker_completion(output, observation)

    assert verified == replace(output, container_observation=observation)
    assert verified is not output
    assert output.container_observation is None


def test_oom_always_rejects_even_when_protocol_output_is_malformed(tmp_path: Path) -> None:
    output = replace(_output(tmp_path), result=cast("WorkerResult", None))

    _assert_rejected(
        output,
        _observation(exit_code=137, oom_killed=True),
        "HOST_WORKER_OOM",
    )


@pytest.mark.parametrize(
    "observation",
    [
        _observation(exit_code=2),
        _observation(exit_code=None, running=True),
        _observation(exit_code=None),
    ],
)
def test_incomplete_or_nonzero_container_exit_rejects_complete_result(
    tmp_path: Path,
    observation: ContainerObservation,
) -> None:
    _assert_rejected(_output(tmp_path), observation, "HOST_WORKER_EXIT_UNEXPECTED")


def test_zero_exit_without_result_is_rejected(tmp_path: Path) -> None:
    malformed = replace(_output(tmp_path), result=cast("WorkerResult", None))

    _assert_rejected(malformed, _observation(), "HOST_RESULT_MISMATCH")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analysis_id", "fw_analysis_ffffffffffffffff"),
        ("status", "partial"),
        ("adapter_id", "archive/zip-v1"),
        ("manifest_sha256", "f" * 64),
        ("emitted_blob_count", 0),
        ("emitted_total_bytes", 0),
        ("warning_codes", ["WORKER_TAR_REJECTED"]),
    ],
)
def test_result_must_match_manifest_and_verified_counts(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    output = _output(tmp_path)
    malformed = replace(output, result=output.result.model_copy(update={field: value}))

    _assert_rejected(malformed, _observation(), "HOST_RESULT_MISMATCH")


def test_raw_manifest_hash_and_parsed_manifest_must_match(tmp_path: Path) -> None:
    output = _output(tmp_path)
    _assert_rejected(
        replace(output, manifest_bytes=output.manifest_bytes + b"\n"),
        _observation(),
        "HOST_RESULT_MISMATCH",
    )
    _assert_rejected(
        replace(output, manifest=output.manifest.model_copy(update={"worker_build_id": "f" * 64})),
        _observation(),
        "HOST_RESULT_MISMATCH",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"blob_id": "blob_00000001"},
        {"size_bytes": len(BLOB_BYTES) - 1},
        {"sha256": "f" * 64},
    ],
)
def test_staging_blob_metadata_must_match_manifest(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    output = _output(tmp_path)
    blob = replace(output.staging_blobs[0], **mutation)  # type: ignore[arg-type]

    _assert_rejected(
        replace(output, staging_blobs=(blob,)),
        _observation(),
        "HOST_RESULT_MISMATCH",
    )
