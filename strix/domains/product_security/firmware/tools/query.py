"""Bounded firmware metadata and summary query tools."""

from __future__ import annotations

from typing import Any, cast

from agents import RunContextWrapper, function_tool

from strix.domains.product_security.firmware.access import require_firmware_permission
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAnalysisRecord,
    FirmwarePermission,
    FirmwareToolResult,
)
from strix.domains.product_security.firmware.service import FirmwareAnalysisService


def firmware_service(ctx: RunContextWrapper[Any]) -> FirmwareAnalysisService:
    raw_context = ctx.context
    context = (
        cast("dict[str, object]", raw_context) if isinstance(raw_context, dict) else {}
    )
    service = context.get("firmware_analysis_service")
    if not isinstance(service, FirmwareAnalysisService):
        raise FirmwareDomainError(
            "FIRMWARE_DOMAIN_NOT_ENABLED",
            "Firmware tools require an enabled Product Security runtime.",
            retryable=False,
        )
    return service


def success_result(
    data: Any,
    *,
    message: str,
    warnings: list[str] | None = None,
) -> str:
    return FirmwareToolResult[Any](
        success=True,
        message=message,
        data=data,
        warnings=warnings or [],
    ).model_dump_json()


def failure_result(exc: FirmwareDomainError) -> str:
    return FirmwareToolResult[Any].from_error(exc).model_dump_json()


def _summary(record: FirmwareAnalysisRecord) -> dict[str, Any]:
    return {
        "analysis_id": record.analysis_id,
        "status": record.status,
        "limitations": record.limitations,
        "created_at": record.created_at,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
    }


@function_tool(timeout=30)
async def list_firmware_jobs(ctx: RunContextWrapper[Any]) -> str:
    """List redacted firmware analysis job summaries for this scan."""
    try:
        require_firmware_permission(ctx, FirmwarePermission.SUMMARY_READ)
        jobs = [_summary(item) for item in firmware_service(ctx).list_analyses()]
        return success_result(
            jobs,
            message=f"Returned {len(jobs)} firmware job summaries.",
        )
    except FirmwareDomainError as exc:
        return failure_result(exc)


@function_tool(timeout=30)
async def get_firmware_summary(
    ctx: RunContextWrapper[Any],
    analysis_id: str,
) -> str:
    """Return one redacted firmware analysis summary."""
    try:
        require_firmware_permission(ctx, FirmwarePermission.SUMMARY_READ)
        record = firmware_service(ctx).get_summary(analysis_id)
        require_firmware_permission(
            ctx,
            FirmwarePermission.SUMMARY_READ,
            input_artifact_id=record.input_artifact_id,
        )
        return success_result(_summary(record), message="Firmware summary returned.")
    except FirmwareDomainError as exc:
        return failure_result(exc)


@function_tool(timeout=30)
async def list_firmware_inputs(ctx: RunContextWrapper[Any]) -> str:
    """List authorized immutable firmware input metadata for this scan."""
    try:
        access = require_firmware_permission(ctx, FirmwarePermission.METADATA_READ)
        inputs = [
            item.model_dump(mode="json")
            for item in firmware_service(ctx).list_inputs()
            if item.input_artifact_id in access.allowed_input_artifact_ids
        ]
        return success_result(inputs, message=f"Returned {len(inputs)} firmware inputs.")
    except FirmwareDomainError as exc:
        return failure_result(exc)


@function_tool(timeout=30)
async def get_firmware_job(
    ctx: RunContextWrapper[Any],
    analysis_id: str,
) -> str:
    """Return full P1 metadata for one authorized firmware analysis job."""
    try:
        require_firmware_permission(ctx, FirmwarePermission.METADATA_READ)
        record = firmware_service(ctx).get_analysis(analysis_id)
        require_firmware_permission(
            ctx,
            FirmwarePermission.METADATA_READ,
            input_artifact_id=record.input_artifact_id,
        )
        return success_result(
            record.model_dump(mode="json"),
            message="Firmware job metadata returned.",
            warnings=record.limitations,
        )
    except FirmwareDomainError as exc:
        return failure_result(exc)
