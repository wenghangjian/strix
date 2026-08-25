"""Final protocol and container verification for firmware worker output."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import TYPE_CHECKING, Never

from pydantic import ValidationError

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.protocol.messages import (
    P2AManifest,
    WorkerResult,
)


if TYPE_CHECKING:
    from strix.domains.product_security.firmware.host.output_receiver import (
        VerifiedWorkerOutput,
    )
    from strix.domains.product_security.firmware.runtime.worker_container import (
        ContainerObservation,
    )


def verify_worker_completion(
    output: VerifiedWorkerOutput,
    observation: ContainerObservation,
) -> VerifiedWorkerOutput:
    if observation.oom_killed:
        _reject(
            "HOST_WORKER_OOM",
            "Firmware worker container was terminated by the OOM killer.",
        )

    _validate_protocol_output(output)
    if observation.running or observation.exit_code != 0:
        _reject(
            "HOST_WORKER_EXIT_UNEXPECTED",
            "Firmware worker container did not exit successfully.",
        )
    return replace(output, container_observation=observation)


def _validate_protocol_output(output: VerifiedWorkerOutput) -> None:
    result = _runtime_value(output.result)
    if not isinstance(result, WorkerResult):
        _result_mismatch()

    actual_manifest_sha256 = hashlib.sha256(output.manifest_bytes).hexdigest()
    if actual_manifest_sha256 != output.manifest_sha256:
        _result_mismatch()
    try:
        parsed_manifest = P2AManifest.model_validate_json(output.manifest_bytes)
    except ValidationError as exc:
        raise FirmwareDomainError(
            "HOST_RESULT_MISMATCH",
            "Verified worker output contains an invalid manifest.",
            retryable=False,
        ) from exc
    if parsed_manifest != output.manifest:
        _result_mismatch()

    manifest = output.manifest
    if (
        result.analysis_id != manifest.analysis_id
        or result.status != manifest.status
        or result.adapter_id != manifest.adapter_id
        or result.manifest_sha256 != output.manifest_sha256
        or result.emitted_blob_count != manifest.blob_count
        or result.emitted_total_bytes != manifest.total_blob_bytes
        or result.warning_codes != manifest.warning_codes
    ):
        _result_mismatch()

    if (
        len(output.staging_blobs) != manifest.blob_count
        or sum(blob.size_bytes for blob in output.staging_blobs)
        != manifest.total_blob_bytes
    ):
        _result_mismatch()
    for staged, declared in zip(
        output.staging_blobs,
        manifest.blobs,
        strict=True,
    ):
        if (
            staged.blob_id != declared.blob_id
            or staged.size_bytes != declared.size_bytes
            or staged.sha256 != declared.sha256
        ):
            _result_mismatch()


def _runtime_value(value: object) -> object:
    return value


def _result_mismatch() -> Never:
    _reject(
        "HOST_RESULT_MISMATCH",
        "Verified worker output does not match its manifest and Result.",
    )


def _reject(error_code: str, message: str) -> Never:
    raise FirmwareDomainError(error_code, message, retryable=False)
