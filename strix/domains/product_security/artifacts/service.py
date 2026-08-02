"""Validated access to Product Security run artifacts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel

from strix.domains.product_security.artifacts.models import (
    AttackSurface,
    DocumentManifest,
    Evidence,
    EvidenceManifest,
    ProductContext,
    TestPathStatus,
    TestPlan,
    TraceableContextItem,
)
from strix.domains.product_security.artifacts.repository import ArtifactCorruptionError


if TYPE_CHECKING:
    from collections.abc import Iterable

    from strix.domains.product_security.artifacts.repository import ArtifactRepository


_PRODUCT_CONTEXT_PATH = "product_context.json"
_ATTACK_SURFACE_PATH = "attack_surface.json"
_TEST_PLAN_PATH = "test_plan.json"
_DOCUMENT_MANIFEST_PATH = "documents/manifest.json"
_EVIDENCE_MANIFEST_PATH = "evidence/manifest.json"
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

ArtifactT = TypeVar("ArtifactT", bound=BaseModel)

_VALID_STATUSES: frozenset[str] = frozenset(
    {
        "candidate",
        "ready",
        "in_progress",
        "blocked",
        "completed",
        "failed",
        "skipped",
    }
)
_STATUS_TRANSITIONS: dict[TestPathStatus, frozenset[TestPathStatus]] = {
    "candidate": frozenset({"ready", "blocked", "skipped"}),
    "ready": frozenset({"in_progress", "blocked", "skipped"}),
    "in_progress": frozenset({"completed", "failed", "blocked"}),
    "blocked": frozenset({"ready", "skipped"}),
    "failed": frozenset({"ready", "skipped"}),
    "completed": frozenset(),
    "skipped": frozenset(),
}


class DomainArtifactError(RuntimeError):
    """Structured Product Security artifact failure."""

    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(message)


class DomainArtifactService:
    """Read, validate, and persist run-scoped domain artifacts."""

    def __init__(self, repository: ArtifactRepository) -> None:
        self.repository = repository

    def get_document_manifest(self) -> DocumentManifest:
        return self._read_json(_DOCUMENT_MANIFEST_PATH, DocumentManifest)

    def read_document_text(self, document_id: str) -> str:
        manifest = self.get_document_manifest()
        document = next(
            (item for item in manifest.documents if item.document_id == document_id),
            None,
        )
        if document is None:
            raise DomainArtifactError(
                "DOMAIN_DOCUMENT_NOT_FOUND",
                f"Document '{document_id}' is not present in the input manifest.",
            )
        try:
            return self.repository.read_text(document.extracted_text_path)
        except OSError as exc:
            raise DomainArtifactError(
                "DOMAIN_ARTIFACT_CORRUPT",
                f"Extracted text for document '{document_id}' is unreadable: {exc}",
            ) from exc

    def get_product_context(self) -> ProductContext:
        return self._read_json(_PRODUCT_CONTEXT_PATH, ProductContext)

    def save_product_context(self, context: ProductContext) -> ProductContext:
        collections = {
            "assets": [item.asset_id for item in context.assets],
            "interfaces": [item.interface_id for item in context.interfaces],
            "protocols": [item.protocol_id for item in context.protocols],
            "trust_boundaries": [item.boundary_id for item in context.trust_boundaries],
            "data_flows": [item.data_flow_id for item in context.data_flows],
            "security_requirements": [
                item.requirement_id for item in context.security_requirements
            ],
            "threats": [item.threat_id for item in context.threats],
            "assumptions": [item.assumption_id for item in context.assumptions],
        }
        for collection_name, stable_ids in collections.items():
            _ensure_unique_ids(collection_name, stable_ids)
        traceable_items: list[TraceableContextItem] = []
        traceable_items.extend(context.assets)
        traceable_items.extend(context.interfaces)
        traceable_items.extend(context.protocols)
        traceable_items.extend(context.trust_boundaries)
        traceable_items.extend(context.data_flows)
        traceable_items.extend(context.security_requirements)
        traceable_items.extend(context.threats)
        traceable_items.extend(context.assumptions)
        for item in traceable_items:
            if item.basis in {"documented_fact", "inference"} and not item.source_ref:
                raise DomainArtifactError(
                    "DOMAIN_MISSING_SOURCE_REF",
                    f"A {item.basis} ProductContext item must contain a source_ref.",
                )
        self.repository.write_json(_PRODUCT_CONTEXT_PATH, context)
        return context

    def get_attack_surface(self) -> AttackSurface:
        return self._read_json(_ATTACK_SURFACE_PATH, AttackSurface)

    def save_attack_surface(self, surface: AttackSurface) -> AttackSurface:
        _ensure_unique_ids("attack_surface.entries", [item.surface_id for item in surface.entries])
        self.repository.write_json(_ATTACK_SURFACE_PATH, surface)
        return surface

    def get_test_plan(self) -> TestPlan:
        return self._read_json(_TEST_PLAN_PATH, TestPlan)

    def save_evidence(self, evidence: Evidence) -> Evidence:
        if not _STABLE_ID_PATTERN.fullmatch(evidence.evidence_id):
            raise DomainArtifactError(
                "DOMAIN_INVALID_STABLE_ID",
                f"Evidence ID '{evidence.evidence_id}' is not a safe stable ID.",
            )
        evidence_path = f"evidence/{evidence.evidence_id}.json"
        manifest_path = self.repository.root / _EVIDENCE_MANIFEST_PATH
        if manifest_path.is_file():
            manifest = self._read_json(_EVIDENCE_MANIFEST_PATH, EvidenceManifest)
        else:
            manifest = EvidenceManifest()
        refs = list(manifest.evidence_refs)
        if evidence_path not in refs:
            refs.append(evidence_path)
        self.repository.write_json(evidence_path, evidence)
        self.repository.write_json(
            _EVIDENCE_MANIFEST_PATH,
            manifest.model_copy(update={"evidence_refs": refs}),
        )
        return evidence

    def save_test_plan(self, plan: TestPlan) -> TestPlan:
        _validate_test_plan(plan)
        updated = plan.model_copy(update={"updated_at": datetime.now(UTC).isoformat()})
        self.repository.write_json(_TEST_PLAN_PATH, updated)
        return updated

    def update_test_path_status(
        self,
        test_path_id: str,
        status: TestPathStatus,
    ) -> TestPlan:
        if status not in _VALID_STATUSES:
            raise DomainArtifactError(
                "DOMAIN_INVALID_TEST_PATH_STATUS",
                f"Unknown TestPath status '{status}'.",
            )
        plan = self.get_test_plan()
        index = next(
            (
                item_index
                for item_index, path in enumerate(plan.test_paths)
                if path.test_path_id == test_path_id
            ),
            None,
        )
        if index is None:
            raise DomainArtifactError(
                "DOMAIN_TEST_PATH_NOT_FOUND",
                f"TestPath '{test_path_id}' is not present in the test plan.",
            )
        current = plan.test_paths[index].status
        if status != current and status not in _STATUS_TRANSITIONS[current]:
            raise DomainArtifactError(
                "DOMAIN_INVALID_STATUS_TRANSITION",
                f"Cannot transition TestPath '{test_path_id}' from '{current}' to '{status}'.",
            )
        updated_paths = list(plan.test_paths)
        updated_paths[index] = updated_paths[index].model_copy(update={"status": status})
        return self.save_test_plan(plan.model_copy(update={"test_paths": updated_paths}))

    def _read_json(self, relative_path: str, model_type: type[ArtifactT]) -> ArtifactT:
        if not (self.repository.root / relative_path).is_file():
            raise DomainArtifactError(
                "DOMAIN_ARTIFACT_NOT_FOUND",
                f"Domain artifact '{relative_path}' does not exist.",
            )
        try:
            return self.repository.read_json(relative_path, model_type)
        except ArtifactCorruptionError as exc:
            raise DomainArtifactError("DOMAIN_ARTIFACT_CORRUPT", str(exc)) from exc

def _ensure_unique_ids(collection_name: str, stable_ids: Iterable[str]) -> None:
    seen: set[str] = set()
    for stable_id in stable_ids:
        if stable_id in seen:
            raise DomainArtifactError(
                "DOMAIN_DUPLICATE_ID",
                f"Duplicate stable ID '{stable_id}' in {collection_name}.",
            )
        seen.add(stable_id)


def _validate_test_plan(plan: TestPlan) -> None:
    path_ids = [path.test_path_id for path in plan.test_paths]
    _ensure_unique_ids("test_plan.test_paths", path_ids)
    known_ids = set(path_ids)
    graph: dict[str, list[str]] = {}
    for path in plan.test_paths:
        if not path.source_refs:
            raise DomainArtifactError(
                "DOMAIN_MISSING_SOURCE_REF",
                f"TestPath '{path.test_path_id}' must contain at least one source reference.",
            )
        unknown = [dependency for dependency in path.depends_on if dependency not in known_ids]
        if unknown:
            raise DomainArtifactError(
                "DOMAIN_INVALID_TEST_PLAN_DAG",
                f"TestPath '{path.test_path_id}' has unknown dependencies: {unknown}.",
            )
        graph[path.test_path_id] = path.depends_on
    _reject_dependency_cycles(graph)


def _reject_dependency_cycles(graph: dict[str, list[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise DomainArtifactError(
                "DOMAIN_INVALID_TEST_PLAN_DAG",
                f"Test Plan contains a dependency cycle at '{node}'.",
            )
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)
