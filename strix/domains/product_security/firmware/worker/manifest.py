"""Archive selection, local outcomes, and deterministic P2a manifests."""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from strix.domains.product_security.firmware.protocol.messages import (
    ArchiveMemberMetadata,
    ArchivePathMetadata,
    P2AManifest,
    P2AManifestBlob,
)
from strix.domains.product_security.firmware.worker.adapters.base import (
    AdapterOutput,
    ArchiveAdapter,
    ArchiveDetectedUnsupported,
    ArchiveRejected,
)
from strix.domains.product_security.firmware.worker.adapters.tar import TarAdapter
from strix.domains.product_security.firmware.worker.adapters.zip import ZipAdapter


if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from pathlib import Path

    from strix.domains.product_security.firmware.protocol.messages import (
        AdapterId,
        AnalysisRequest,
    )
    from strix.domains.product_security.firmware.worker.limits import WorkerLimits
    from strix.domains.product_security.firmware.worker.staging import (
        StagedInput,
        WorkerStaging,
    )


LocalWorkerStatus = Literal[
    "rejected",
    "detected_unsupported",
    "not_applicable",
    "unclassified",
]


@dataclass(frozen=True, slots=True)
class LocalStatus:
    status: LocalWorkerStatus
    adapter_id: AdapterId | None = None
    adapter_version: str | None = None
    warning_codes: tuple[str, ...] = ()
    rejected_entry_count: int = 0
    ignored_directory_count: int = 0


def select_archive_adapter(
    input_path: Path,
    enabled_adapters: Sequence[AdapterId],
) -> ArchiveAdapter | LocalStatus:
    tar_detected = tarfile.is_tarfile(input_path)
    zip_detected = zipfile.is_zipfile(input_path)
    if tar_detected and zip_detected:
        return LocalStatus(
            status="unclassified",
            warning_codes=("WORKER_FORMAT_AMBIGUOUS",),
        )
    if tar_detected:
        if "archive/tar-v1" in enabled_adapters:
            return TarAdapter()
        return LocalStatus(
            status="detected_unsupported",
            adapter_id="archive/tar-v1",
            adapter_version="1.0",
        )
    if zip_detected:
        if "archive/zip-v1" in enabled_adapters:
            return ZipAdapter()
        return LocalStatus(
            status="detected_unsupported",
            adapter_id="archive/zip-v1",
            adapter_version="1.0",
        )
    return LocalStatus(status="not_applicable")


def analyze_archive(
    *,
    input_path: Path,
    enabled_adapters: Sequence[AdapterId],
    limits: WorkerLimits,
    staging: WorkerStaging,
) -> AdapterOutput | LocalStatus:
    selected = select_archive_adapter(input_path, enabled_adapters)
    if isinstance(selected, LocalStatus):
        return selected
    try:
        preflight = selected.preflight(input_path, limits)
        return selected.extract(input_path, preflight, staging)
    except ArchiveDetectedUnsupported:
        return LocalStatus(
            status="detected_unsupported",
            adapter_id=_adapter_id(selected.adapter_id),
            adapter_version="1.0",
        )
    except ArchiveRejected:
        return LocalStatus(
            status="rejected",
            adapter_id=_adapter_id(selected.adapter_id),
            adapter_version="1.0",
            warning_codes=(_rejection_code(selected.adapter_id),),
            rejected_entry_count=1,
        )


def build_manifest(
    *,
    request: AnalysisRequest,
    staged_input: StagedInput,
    analysis: AdapterOutput | LocalStatus,
    worker_build_id: str,
    generated_at_utc: datetime,
) -> P2AManifest:
    if (
        staged_input.size != request.declared_input_size
        or staged_input.sha256 != request.declared_input_sha256
    ):
        raise ValueError("staged input identity does not match the analysis request")

    if isinstance(analysis, LocalStatus):
        return P2AManifest(
            manifest_schema="p2a-manifest-1",
            protocol_version="1.0",
            analysis_id=request.analysis_id,
            input_artifact_id=request.input_artifact_id,
            input_size=staged_input.size,
            input_sha256=staged_input.sha256,
            adapter_id=analysis.adapter_id,
            adapter_version=analysis.adapter_version,
            status=analysis.status,
            generated_at_utc=generated_at_utc,
            worker_build_id=worker_build_id,
            blob_count=0,
            total_blob_bytes=0,
            blobs=[],
            warning_codes=list(analysis.warning_codes),
            rejected_entry_count=analysis.rejected_entry_count,
            ignored_directory_count=analysis.ignored_directory_count,
            limits_profile="p2a-default-v1",
        )

    adapter_id = _adapter_id(analysis.adapter_id)
    blobs: list[P2AManifestBlob] = []
    for ordinal, extracted in enumerate(analysis.members):
        planned = extracted.preflight
        blob_name = f"blob_{ordinal:08d}"
        blobs.append(
            P2AManifestBlob(
                blob_id=blob_name,
                stream_id=4096 + ordinal,
                ordinal=ordinal,
                generated_storage_name=blob_name,
                size_bytes=extracted.actual_size,
                sha256=extracted.sha256,
                relation="extracted",
                parent_input_artifact_id=request.input_artifact_id,
                path=ArchivePathMetadata(
                    display_path=planned.path.display_path,
                    canonical_path=planned.path.canonical_path,
                    raw_name_b64=planned.path.raw_name_b64,
                    path_encoding=planned.path.path_encoding,
                ),
                archive=ArchiveMemberMetadata(
                    member_index=planned.member_index,
                    member_type="regular_file",
                    declared_size=planned.declared_size,
                    actual_size=extracted.actual_size,
                    compression_method=planned.compression_method,
                    crc32=planned.crc32,
                    unix_mode=planned.unix_mode,
                    uid=planned.uid,
                    gid=planned.gid,
                    mtime_utc=planned.mtime_utc,
                ),
            )
        )
    return P2AManifest(
        manifest_schema="p2a-manifest-1",
        protocol_version="1.0",
        analysis_id=request.analysis_id,
        input_artifact_id=request.input_artifact_id,
        input_size=staged_input.size,
        input_sha256=staged_input.sha256,
        adapter_id=adapter_id,
        adapter_version=analysis.adapter_version,
        status="complete",
        generated_at_utc=generated_at_utc,
        worker_build_id=worker_build_id,
        blob_count=len(blobs),
        total_blob_bytes=sum(blob.size_bytes for blob in blobs),
        blobs=blobs,
        warning_codes=[],
        rejected_entry_count=0,
        ignored_directory_count=analysis.ignored_directory_count,
        limits_profile="p2a-default-v1",
    )


def _adapter_id(value: str) -> AdapterId:
    if value == "archive/tar-v1":
        return "archive/tar-v1"
    if value == "archive/zip-v1":
        return "archive/zip-v1"
    raise ValueError("unknown archive adapter identity")


def _rejection_code(adapter_id: str) -> str:
    if adapter_id == "archive/tar-v1":
        return "WORKER_TAR_REJECTED"
    if adapter_id == "archive/zip-v1":
        return "WORKER_ZIP_REJECTED"
    raise ValueError("unknown archive adapter identity")
