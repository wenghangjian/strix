from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from strix.domains.product_security.bootstrap import enable_product_security_domain
from strix.domains.product_security.config import ProductSecurityConfig
from strix.domains.product_security.firmware.tools import start_firmware_analysis


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_bootstrap_ingests_once_and_resume_reuses_state(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"synthetic-firmware")
    run_dir = tmp_path / "run"
    config = ProductSecurityConfig(
        profile="product-security",
        artifacts=[str(source)],
    )

    first = enable_product_security_domain(config, run_dir, scan_id="scan-1")
    artifact = first.firmware_service.list_inputs()[0]
    access = first.firmware_access_issuer.issue(
        agent_id="firmware-child",
        role_profile=first.role_registry.get("firmware_analyst"),
    )
    arguments = json.dumps({"input_artifact_id": artifact.input_artifact_id})
    context = ToolContext(
        context={
            "agent_id": "firmware-child",
            "firmware_access": access,
            "firmware_analysis_service": first.firmware_service,
        },
        tool_name=start_firmware_analysis.name,
        tool_call_id="call-p1-acceptance",
        tool_arguments=arguments,
    )
    queued = json.loads(await start_firmware_analysis.on_invoke_tool(context, arguments))

    source.unlink()
    resumed = enable_product_security_domain(
        config,
        run_dir,
        scan_id="scan-1",
        resume=True,
    )

    assert queued["success"] is True
    assert len(resumed.firmware_service.list_inputs()) == 1
    assert len(resumed.firmware_service.list_analyses()) == 1
    assert len(list(resumed.firmware_repository.blob_root.rglob(artifact.sha256))) == 1


def test_disabled_bootstrap_creates_no_firmware_state(tmp_path: Path) -> None:
    runtime = enable_product_security_domain(
        ProductSecurityConfig(profile=None),
        tmp_path / "run",
        scan_id="scan-disabled",
    )

    assert runtime.enabled is False
    assert runtime.root_tools == ()
    assert runtime.role_tools == ()
    assert not (tmp_path / "run" / "domain" / "firmware").exists()
