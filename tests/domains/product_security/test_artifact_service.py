from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.artifacts.models import (
    Asset,
    DocumentArtifact,
    DocumentManifest,
    ProductContext,
)
from strix.domains.product_security.artifacts.models import (
    TestPath as DomainTestPath,
)
from strix.domains.product_security.artifacts.models import (
    TestPlan as DomainTestPlan,
)
from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.artifacts.service import (
    DomainArtifactError,
    DomainArtifactService,
)


if TYPE_CHECKING:
    from pathlib import Path


def _path(path_id: str, *, depends_on: list[str] | None = None) -> DomainTestPath:
    return DomainTestPath(
        test_path_id=path_id,
        title=f"Test {path_id}",
        objective="Verify an access control.",
        source_refs=["doc_manual"],
        affected_assets=["asset_controller"],
        threat_refs=[],
        requirement_refs=["req_auth"],
        prerequisites=[],
        steps=[],
        success_condition="Unauthorized access is rejected.",
        risk_level="L1",
        confidence=0.8,
        recommended_role="protocol_security_tester",
        depends_on=depends_on or [],
    )


def test_service_reads_extracted_document_by_stable_id(tmp_path: Path) -> None:
    repository = ArtifactRepository(tmp_path / "run")
    repository.write_text("documents/extracted/doc_manual.txt", "Modbus TCP is enabled.")
    repository.write_json(
        "documents/manifest.json",
        DocumentManifest(
            documents=[
                DocumentArtifact(
                    document_id="doc_manual",
                    source_path="manual.md",
                    file_name="manual.md",
                    content_type="text/markdown",
                    size_bytes=23,
                    sha256="a" * 64,
                    extracted_text_path="documents/extracted/doc_manual.txt",
                )
            ]
        ),
    )
    service = DomainArtifactService(repository)

    assert service.read_document_text("doc_manual") == "Modbus TCP is enabled."


def test_service_persists_product_context(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    context = ProductContext(
        project_id="controller-audit",
        assets=[
            Asset(
                asset_id="asset_controller",
                name="Controller",
                source_ref="doc_manual",
                basis="documented_fact",
                confidence=1.0,
            )
        ],
    )

    service.save_product_context(context)

    assert service.get_product_context() == context


def test_service_rejects_duplicate_product_context_ids(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    duplicate = ProductContext(
        project_id="controller-audit",
        assets=[
            Asset(asset_id="asset_controller", name="Controller A"),
            Asset(asset_id="asset_controller", name="Controller B"),
        ],
    )

    with pytest.raises(DomainArtifactError) as exc:
        service.save_product_context(duplicate)

    assert exc.value.error_code == "DOMAIN_DUPLICATE_ID"
    assert "asset_controller" in exc.value.message


def test_service_rejects_test_plan_with_unknown_dependency(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    plan = DomainTestPlan(
        project_id="controller-audit",
        test_paths=[_path("path-1", depends_on=["missing-path"])],
    )

    with pytest.raises(DomainArtifactError) as exc:
        service.save_test_plan(plan)

    assert exc.value.error_code == "DOMAIN_INVALID_TEST_PLAN_DAG"
    assert "missing-path" in exc.value.message


def test_service_rejects_test_plan_dependency_cycle(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    plan = DomainTestPlan(
        project_id="controller-audit",
        test_paths=[
            _path("path-1", depends_on=["path-2"]),
            _path("path-2", depends_on=["path-1"]),
        ],
    )

    with pytest.raises(DomainArtifactError) as exc:
        service.save_test_plan(plan)

    assert exc.value.error_code == "DOMAIN_INVALID_TEST_PLAN_DAG"
    assert "cycle" in exc.value.message


def test_service_persists_valid_test_path_status_sequence(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    service.save_test_plan(
        DomainTestPlan(project_id="controller-audit", test_paths=[_path("path-1")])
    )

    service.update_test_path_status("path-1", "ready")
    service.update_test_path_status("path-1", "in_progress")
    updated = service.update_test_path_status("path-1", "completed")

    assert updated.test_paths[0].status == "completed"
    assert service.get_test_plan().test_paths[0].status == "completed"


def test_service_rejects_transition_from_completed_to_in_progress(tmp_path: Path) -> None:
    service = DomainArtifactService(ArtifactRepository(tmp_path / "run"))
    path = _path("path-1")
    path.status = "completed"
    service.save_test_plan(DomainTestPlan(project_id="controller-audit", test_paths=[path]))

    with pytest.raises(DomainArtifactError) as exc:
        service.update_test_path_status("path-1", "in_progress")

    assert exc.value.error_code == "DOMAIN_INVALID_STATUS_TRANSITION"
    assert "completed" in exc.value.message
    assert "in_progress" in exc.value.message
