from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.domains.product_security.artifacts.models import (
    ProductContext,
)
from strix.domains.product_security.artifacts.models import (
    TestPlan as DomainTestPlan,
)
from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.documents.ingestion import ingest_documents
from strix.domains.product_security.tools import (
    get_document_manifest,
    query_test_plan,
    write_attack_surface,
    write_product_context,
    write_test_plan,
)


if TYPE_CHECKING:
    from pathlib import Path

    from agents.tool import FunctionTool


async def _invoke(
    tool: FunctionTool,
    arguments: dict[str, Any],
    repository: ArtifactRepository,
) -> dict[str, Any]:
    serialized = json.dumps(arguments)
    context = ToolContext(
        context={"product_security_artifacts": repository},
        tool_name=tool.name,
        tool_call_id="call-phase2-acceptance",
        tool_arguments=serialized,
    )
    return json.loads(await tool.on_invoke_tool(context, serialized))


@pytest.mark.asyncio
async def test_documented_context_fact_requires_source_reference(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    payload = ProductContext.model_validate(
        {
            "project_id": "controller-audit",
            "assets": [
                {
                    "asset_id": "asset-controller",
                    "name": "Controller",
                    "basis": "documented_fact",
                    "confidence": 1.0,
                }
            ],
        }
    )

    result = await _invoke(
        write_product_context,
        {"payload": payload.model_dump_json()},
        repository,
    )

    assert result["success"] is False
    assert result["error_code"] == "DOMAIN_MISSING_SOURCE_REF"


@pytest.mark.asyncio
async def test_phase2_documents_to_traceable_five_path_plan(tmp_path: Path) -> None:
    manual = tmp_path / "product-manual.md"
    manual_copy = tmp_path / "product-manual-copy.md"
    threat_model = tmp_path / "threat-model.md"
    requirements = tmp_path / "security-requirements.md"
    manual.write_text(
        "# ACME Controller\nEthernet exposes Modbus TCP on port 502.\n",
        encoding="utf-8",
    )
    manual_copy.write_text(manual.read_text(encoding="utf-8"), encoding="utf-8")
    threat_model.write_text(
        "# Threat Model\nRemote clients may attempt unauthenticated control.\n",
        encoding="utf-8",
    )
    requirements.write_text(
        "# Requirements\nREQ-1: Remote control requires authentication.\n",
        encoding="utf-8",
    )
    repository = ArtifactRepository(tmp_path / "run")
    manifest = ingest_documents(
        [str(manual), str(manual_copy), str(threat_model), str(requirements)],
        repository,
    )
    document_ids = {item.file_name: item.document_id for item in manifest.documents}
    manual_ref = document_ids["product-manual.md"]
    threat_ref = document_ids["threat-model.md"]
    requirement_ref = document_ids["security-requirements.md"]

    manifest_result = await _invoke(get_document_manifest, {}, repository)
    context_result = await _invoke(
        write_product_context,
        {
            "payload": json.dumps(
                {
                    "project_id": "controller-audit",
                    "product_name": "ACME Controller",
                    "product_type": "industrial controller",
                    "assets": [
                        {
                            "asset_id": "asset-controller",
                            "name": "Controller",
                            "asset_type": "OT device",
                            "source_ref": manual_ref,
                            "basis": "documented_fact",
                            "confidence": 1.0,
                        }
                    ],
                    "interfaces": [
                        {
                            "interface_id": "interface-ethernet",
                            "name": "Ethernet",
                            "interface_type": "network",
                            "protocol_refs": ["protocol-modbus-tcp"],
                            "source_ref": manual_ref,
                            "basis": "documented_fact",
                            "confidence": 1.0,
                        }
                    ],
                    "protocols": [
                        {
                            "protocol_id": "protocol-modbus-tcp",
                            "name": "Modbus TCP",
                            "transport": "TCP",
                            "port": 502,
                            "source_ref": manual_ref,
                            "basis": "documented_fact",
                            "confidence": 1.0,
                        }
                    ],
                    "trust_boundaries": [
                        {
                            "boundary_id": "boundary-remote-client",
                            "name": "Remote client to controller",
                            "source_ref": threat_ref,
                            "basis": "inference",
                            "confidence": 0.8,
                        }
                    ],
                    "security_requirements": [
                        {
                            "requirement_id": "req-1",
                            "statement": "Remote control requires authentication.",
                            "source_ref": requirement_ref,
                            "basis": "documented_fact",
                            "confidence": 1.0,
                        }
                    ],
                    "threats": [
                        {
                            "threat_id": "threat-unauthenticated-control",
                            "statement": "A remote client may issue unauthenticated commands.",
                            "basis": "documented_fact",
                            "source_ref": threat_ref,
                            "confidence": 1.0,
                        }
                    ],
                    "evidence_refs": [manual_ref, threat_ref, requirement_ref],
                }
            )
        },
        repository,
    )
    surface_result = await _invoke(
        write_attack_surface,
        {
            "payload": json.dumps(
                {
                    "project_id": "controller-audit",
                    "entries": [
                        {
                            "surface_id": "surface-modbus",
                            "name": "Modbus TCP service",
                            "category": "network service",
                            "state": "declared",
                            "asset_refs": ["asset-controller"],
                            "interface_refs": ["interface-ethernet"],
                            "protocol_refs": ["protocol-modbus-tcp"],
                            "source_refs": [manual_ref],
                            "confidence": 1.0,
                        }
                    ],
                }
            )
        },
        repository,
    )
    test_paths = []
    for index, source_ref in enumerate(
        [manual_ref, threat_ref, requirement_ref, manual_ref, requirement_ref],
        start=1,
    ):
        test_paths.append(
            {
                "test_path_id": f"path-{index}",
                "title": f"Controller security test {index}",
                "objective": "Verify the documented controller security behavior.",
                "source_refs": [source_ref],
                "affected_assets": ["asset-controller"],
                "threat_refs": ["threat-unauthenticated-control"],
                "requirement_refs": ["req-1"],
                "prerequisites": ["Use an isolated simulated target."],
                "steps": [],
                "expected_security_control": "Authentication gates remote control.",
                "success_condition": "Unauthorized control is rejected.",
                "risk_level": "L1",
                "confidence": 0.8,
                "recommended_role": "protocol_security_tester",
                "depends_on": [] if index == 1 else ["path-1"],
                "parallelizable": index > 1,
                "requires_approval": False,
                "status": "candidate",
            }
        )
    plan_result = await _invoke(
        write_test_plan,
        {
            "payload": json.dumps(
                {"project_id": "controller-audit", "test_paths": test_paths}
            )
        },
        repository,
    )
    queried_plan = await _invoke(query_test_plan, {}, repository)

    assert len(manifest.documents) == 3
    assert manifest_result["success"] is True
    assert context_result["success"] is True
    assert surface_result["success"] is True
    assert plan_result["success"] is True
    assert queried_plan["success"] is True
    context = repository.read_json("product_context.json", ProductContext)
    plan = repository.read_json("test_plan.json", DomainTestPlan)
    assert len(context.assets) == 1
    assert len(plan.test_paths) == 5
    assert all(path.source_refs for path in plan.test_paths)
