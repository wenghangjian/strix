from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from strix.domains.product_security.artifacts.models import (
    Asset,
    AttackSurface,
    AttackSurfaceEntry,
)
from strix.domains.product_security.artifacts.models import (
    TestPath as DomainTestPath,
)
from strix.domains.product_security.artifacts.models import (
    TestPlan as DomainTestPlan,
)
from strix.domains.product_security.artifacts.models import (
    TestStep as DomainTestStep,
)
from strix.domains.product_security.artifacts.repository import ArtifactRepository


if TYPE_CHECKING:
    from pathlib import Path


def _test_path(index: int) -> DomainTestPath:
    return DomainTestPath(
        test_path_id=f"path-{index}",
        title=f"Security path {index}",
        objective="Verify the documented security control.",
        source_refs=["doc_manual"],
        affected_assets=["asset_controller"],
        threat_refs=["threat_remote_access"],
        requirement_refs=["req_authentication"],
        prerequisites=["Product is available in an isolated lab."],
        steps=[
            DomainTestStep(
                step_id=f"step-{index}",
                description="Inspect the exposed interface.",
                expected_result="The interface requires authentication.",
            )
        ],
        expected_security_control="Authentication is enforced.",
        success_condition="Unauthenticated access is rejected.",
        risk_level="L1",
        confidence=0.8,
        recommended_role="protocol_security_tester",
        depends_on=[] if index == 1 else ["path-1"],
        parallelizable=index > 1,
        requires_approval=False,
        status="candidate",
    )


def test_context_entry_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Asset(
            asset_id="asset_controller",
            name="Controller",
            basis="documented_fact",
            confidence=1.1,
        )


def test_test_plan_round_trips_dag_and_approval_fields(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    plan = DomainTestPlan(
        project_id="controller-audit",
        test_paths=[_test_path(i) for i in range(1, 6)],
    )

    repository.write_json("test_plan.json", plan)

    persisted = repository.read_json("test_plan.json", DomainTestPlan)
    assert len(persisted.test_paths) == 5
    assert persisted.test_paths[1].depends_on == ["path-1"]
    assert persisted.test_paths[1].parallelizable is True
    assert persisted.test_paths[1].requires_approval is False
    assert persisted.test_paths[1].source_refs == ["doc_manual"]


def test_attack_surface_records_declared_and_observed_delta() -> None:
    surface = AttackSurface(
        project_id="controller-audit",
        entries=[
            AttackSurfaceEntry(
                surface_id="surface-debug-port",
                name="Debug interface",
                category="debug",
                state="undocumented",
                asset_refs=["asset_controller"],
                interface_refs=["interface_uart"],
                source_refs=["scan_nmap"],
                confidence=0.95,
            )
        ],
    )

    assert surface.entries[0].state == "undocumented"
    assert surface.entries[0].source_refs == ["scan_nmap"]
