from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.domains.product_security.firmware.access import FirmwareAccessIssuer
from strix.domains.product_security.firmware.ingestion import ingest_firmware_inputs
from strix.domains.product_security.firmware.repository import FirmwareRepository
from strix.domains.product_security.firmware.service import FirmwareAnalysisService
from strix.domains.product_security.firmware.tools import (
    get_firmware_summary,
    list_firmware_inputs,
    start_firmware_analysis,
)
from strix.domains.product_security.roles.registry import default_role_registry


if TYPE_CHECKING:
    from pathlib import Path

    from agents.tool import FunctionTool


async def _invoke(
    tool: FunctionTool,
    arguments: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    serialized = json.dumps(arguments)
    tool_context = ToolContext(
        context=context,
        tool_name=tool.name,
        tool_call_id="call-firmware-tool",
        tool_arguments=serialized,
    )
    return json.loads(await tool.on_invoke_tool(tool_context, serialized))


def _firmware_context(tmp_path: Path, *, role_id: str) -> tuple[dict[str, Any], str]:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"firmware-image")
    repository = FirmwareRepository(tmp_path / "run")
    repository.initialize()
    artifact = ingest_firmware_inputs(
        [str(source)],
        repository,
        scan_id="scan-1",
        source_type="fixture",
    )[0]
    issuer = FirmwareAccessIssuer(
        scan_id="scan-1",
        allowed_input_artifact_ids={artifact.input_artifact_id},
    )
    agent_id = "root" if role_id == "root" else "child"
    access = (
        issuer.issue_root(agent_id=agent_id)
        if role_id == "root"
        else issuer.issue(
            agent_id=agent_id,
            role_profile=default_role_registry().get(role_id),
        )
    )
    return (
        {
            "agent_id": agent_id,
            "firmware_access": access,
            "firmware_analysis_service": FirmwareAnalysisService(
                repository,
                scan_id="scan-1",
            ),
        },
        artifact.input_artifact_id,
    )


@pytest.mark.asyncio
async def test_firmware_analyst_can_queue_allowed_input(tmp_path: Path) -> None:
    context, input_id = _firmware_context(tmp_path, role_id="firmware_analyst")

    result = await _invoke(
        start_firmware_analysis,
        {"input_artifact_id": input_id},
        context,
    )

    assert result["success"] is True
    assert result["data"]["status"] == "queued"
    assert result["data"]["input_artifact_id"] == input_id
    assert result["warnings"] == ["Firmware worker is not available until Phase P2a."]


@pytest.mark.asyncio
async def test_root_cannot_directly_queue_firmware_analysis(tmp_path: Path) -> None:
    context, input_id = _firmware_context(tmp_path, role_id="root")

    result = await _invoke(
        start_firmware_analysis,
        {"input_artifact_id": input_id},
        context,
    )

    assert result == {
        "success": False,
        "error_code": "FIRMWARE_ACCESS_DENIED",
        "message": "Firmware permission 'firmware.worker.execute' is not granted.",
        "retryable": False,
        "data": None,
        "artifact_refs": [],
        "warnings": [],
    }


@pytest.mark.asyncio
async def test_non_firmware_role_cannot_directly_list_inputs(tmp_path: Path) -> None:
    context, _ = _firmware_context(tmp_path, role_id="test_planner")

    result = await _invoke(list_firmware_inputs, {}, context)

    assert result["success"] is False
    assert result["error_code"] == "FIRMWARE_ACCESS_DENIED"


@pytest.mark.asyncio
async def test_root_summary_is_redacted(tmp_path: Path) -> None:
    analyst_context, input_id = _firmware_context(tmp_path, role_id="firmware_analyst")
    queued = await _invoke(
        start_firmware_analysis,
        {"input_artifact_id": input_id},
        analyst_context,
    )
    issuer = FirmwareAccessIssuer(
        scan_id="scan-1",
        allowed_input_artifact_ids={input_id},
    )
    root_context = {
        **analyst_context,
        "agent_id": "root",
        "firmware_access": issuer.issue_root(agent_id="root"),
    }

    result = await _invoke(
        get_firmware_summary,
        {"analysis_id": queued["data"]["analysis_id"]},
        root_context,
    )

    assert result["success"] is True
    assert "input_artifact_id" not in result["data"]
    assert result["data"]["status"] == "queued"

