"""Authorized P1 firmware analysis queue tool."""

from __future__ import annotations

from typing import Any

from agents import RunContextWrapper, function_tool

from strix.domains.product_security.firmware.access import require_firmware_permission
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import FirmwarePermission
from strix.domains.product_security.firmware.tools.query import (
    _failure,
    _service,
    _success,
)


@function_tool(timeout=30)
async def start_firmware_analysis(
    ctx: RunContextWrapper[Any],
    input_artifact_id: str,
) -> str:
    """Queue one authorized immutable firmware input for future worker analysis."""
    try:
        require_firmware_permission(
            ctx,
            FirmwarePermission.WORKER_EXECUTE,
            input_artifact_id=input_artifact_id,
        )
        record = _service(ctx).queue_analysis(input_artifact_id)
        return _success(
            record.model_dump(mode="json"),
            message="Firmware analysis queued.",
            warnings=record.limitations,
        )
    except FirmwareDomainError as exc:
        return _failure(exc)
