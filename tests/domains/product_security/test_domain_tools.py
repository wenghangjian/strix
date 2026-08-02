from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.domains.product_security.artifacts.models import (
    Evidence,
    ProductContext,
)
from strix.domains.product_security.artifacts.models import (
    TestPlan as DomainTestPlan,
)
from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.tools import (
    create_evidence,
    get_product_context,
    query_domain_artifact,
    update_test_path_status,
    write_product_context,
    write_test_plan,
)


if TYPE_CHECKING:
    from pathlib import Path

    from agents.tool import FunctionTool


async def _invoke(
    tool: FunctionTool,
    arguments: dict[str, Any],
    repository: ArtifactRepository | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {}
    if repository is not None:
        context["product_security_artifacts"] = repository
    serialized = json.dumps(arguments)
    tool_context = ToolContext(
        context=context,
        tool_name=tool.name,
        tool_call_id="call-domain-tool",
        tool_arguments=serialized,
    )
    return json.loads(await tool.on_invoke_tool(tool_context, serialized))


@pytest.mark.asyncio
async def test_domain_tool_rejects_missing_profile_context() -> None:
    result = await _invoke(get_product_context, {})

    assert result["success"] is False
    assert result["error_code"] == "PRODUCT_SECURITY_DOMAIN_NOT_ENABLED"


@pytest.mark.asyncio
async def test_write_product_context_rejects_malformed_payload(tmp_path: Path) -> None:
    result = await _invoke(
        write_product_context,
        {"payload": "{broken"},
        ArtifactRepository(tmp_path / "run"),
    )

    assert result["success"] is False
    assert result["error_code"] == "DOMAIN_VALIDATION_FAILED"


@pytest.mark.asyncio
async def test_write_product_context_persists_validated_artifact(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    context = ProductContext(project_id="controller-audit")

    result = await _invoke(
        write_product_context,
        {"payload": context.model_dump_json()},
        repository,
    )

    assert result["success"] is True
    assert result["artifact"] == "product_context.json"
    assert repository.read_json("product_context.json", ProductContext) == context


@pytest.mark.asyncio
async def test_update_test_path_status_persists_through_tool(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    plan = {
        "project_id": "controller-audit",
        "test_paths": [
            {
                "test_path_id": "path-1",
                "title": "Authentication check",
                "objective": "Verify authentication.",
                "source_refs": ["doc_manual"],
                "success_condition": "Anonymous access is rejected.",
                "risk_level": "L1",
                "confidence": 0.8,
                "recommended_role": "protocol_security_tester",
            }
        ],
    }
    created = await _invoke(
        write_test_plan,
        {"payload": json.dumps(plan)},
        repository,
    )

    updated = await _invoke(
        update_test_path_status,
        {"test_path_id": "path-1", "status": "ready"},
        repository,
    )

    assert created["success"] is True
    assert updated["success"] is True
    assert repository.read_json("test_plan.json", DomainTestPlan).test_paths[0].status == "ready"


@pytest.mark.asyncio
async def test_query_domain_artifact_rejects_path_traversal(tmp_path: Path) -> None:
    result = await _invoke(
        query_domain_artifact,
        {"relative_path": "../agents.json"},
        ArtifactRepository(tmp_path / "run"),
    )

    assert result["success"] is False
    assert result["error_code"] == "DOMAIN_INVALID_ARTIFACT_PATH"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "relative_path",
    [
        "firmware/inputs/item.json",
        "firmware/blobs/sha256/aa/value",
        "firmware/staging/pending.blob",
        "firmware/firmware.db",
    ],
)
async def test_query_domain_artifact_rejects_private_firmware_namespace(
    tmp_path: Path,
    relative_path: str,
) -> None:
    result = await _invoke(
        query_domain_artifact,
        {"relative_path": relative_path},
        ArtifactRepository(tmp_path / "run"),
    )

    assert result["success"] is False
    assert result["error_code"] == "FIRMWARE_ACCESS_DENIED"


@pytest.mark.asyncio
async def test_create_evidence_writes_item_and_manifest(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    evidence = Evidence(
        evidence_id="evidence-auth-1",
        evidence_type="document",
        source="doc_manual",
        agent_id="prerequisite-agent",
        test_path_id="path-1",
    )

    result = await _invoke(
        create_evidence,
        {"payload": evidence.model_dump_json()},
        repository,
    )

    manifest = json.loads(repository.read_text("evidence/manifest.json"))
    assert result["success"] is True
    assert repository.read_json("evidence/evidence-auth-1.json", Evidence) == evidence
    assert manifest["evidence_refs"] == ["evidence/evidence-auth-1.json"]
