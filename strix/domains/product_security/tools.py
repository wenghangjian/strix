"""Run-scoped SDK tools for the Product Security profile."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool
from pydantic import ValidationError

from strix.domains.product_security.artifacts.models import (
    AttackSurface,
    Evidence,
    ProductContext,
    TestPathStatus,
    TestPlan,
)
from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.artifacts.service import (
    DomainArtifactError,
    DomainArtifactService,
)


if TYPE_CHECKING:
    from agents.tool import Tool


def _repository(ctx: RunContextWrapper[Any]) -> ArtifactRepository:
    context = ctx.context
    repository = context.get("product_security_artifacts") if isinstance(context, dict) else None
    if not isinstance(repository, ArtifactRepository):
        raise DomainArtifactError(
            "PRODUCT_SECURITY_DOMAIN_NOT_ENABLED",
            "Product Security artifact tools require the product-security profile.",
        )
    return repository


def _service(ctx: RunContextWrapper[Any]) -> DomainArtifactService:
    return DomainArtifactService(_repository(ctx))


def _response(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _error_response(exc: DomainArtifactError | ValidationError) -> str:
    if isinstance(exc, DomainArtifactError):
        return _response(
            {"success": False, "error_code": exc.error_code, "error": exc.message}
        )
    return _response(
        {
            "success": False,
            "error_code": "DOMAIN_VALIDATION_FAILED",
            "error": str(exc),
        }
    )


@function_tool(timeout=30)
async def get_document_manifest(ctx: RunContextWrapper[Any]) -> str:
    """Return the deduplicated Product Security input document manifest."""
    try:
        manifest = _service(ctx).get_document_manifest()
        return _response({"success": True, "manifest": manifest.model_dump(mode="json")})
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def read_document_text(ctx: RunContextWrapper[Any], document_id: str) -> str:
    """Read extracted text for one manifest document ID."""
    try:
        content = _service(ctx).read_document_text(document_id)
        return _response({"success": True, "document_id": document_id, "content": content})
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def query_domain_artifact(ctx: RunContextWrapper[Any], relative_path: str) -> str:
    """Read a text or JSON artifact below the current run's domain directory."""
    try:
        repository = _repository(ctx)
        content = repository.read_text(relative_path)
        try:
            parsed: Any = json.loads(content)
        except json.JSONDecodeError:
            parsed = content
        return _response(
            {"success": True, "relative_path": relative_path, "content": parsed}
        )
    except ValueError as exc:
        return _error_response(DomainArtifactError("DOMAIN_INVALID_ARTIFACT_PATH", str(exc)))
    except OSError as exc:
        return _error_response(DomainArtifactError("DOMAIN_ARTIFACT_NOT_FOUND", str(exc)))
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def get_product_context(ctx: RunContextWrapper[Any]) -> str:
    """Return the persisted ProductContext for this scan."""
    try:
        context = _service(ctx).get_product_context()
        return _response(
            {"success": True, "product_context": context.model_dump(mode="json")}
        )
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def write_product_context(ctx: RunContextWrapper[Any], payload: str) -> str:
    """Validate and atomically persist a ProductContext JSON payload."""
    try:
        context = ProductContext.model_validate_json(payload)
        saved = _service(ctx).save_product_context(context)
        return _response(
            {
                "success": True,
                "artifact": "product_context.json",
                "product_context": saved.model_dump(mode="json"),
            }
        )
    except (DomainArtifactError, ValidationError) as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def get_attack_surface(ctx: RunContextWrapper[Any]) -> str:
    """Return the declared/observed Product Security attack surface."""
    try:
        surface = _service(ctx).get_attack_surface()
        return _response({"success": True, "attack_surface": surface.model_dump(mode="json")})
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def write_attack_surface(ctx: RunContextWrapper[Any], payload: str) -> str:
    """Validate and atomically persist an AttackSurface JSON payload."""
    try:
        surface = AttackSurface.model_validate_json(payload)
        saved = _service(ctx).save_attack_surface(surface)
        return _response(
            {
                "success": True,
                "artifact": "attack_surface.json",
                "attack_surface": saved.model_dump(mode="json"),
            }
        )
    except (DomainArtifactError, ValidationError) as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def query_test_plan(ctx: RunContextWrapper[Any]) -> str:
    """Return the persisted explicit Product Security Test Plan DAG."""
    try:
        plan = _service(ctx).get_test_plan()
        return _response({"success": True, "test_plan": plan.model_dump(mode="json")})
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def write_test_plan(ctx: RunContextWrapper[Any], payload: str) -> str:
    """Validate and atomically persist a Product Security Test Plan JSON payload."""
    try:
        plan = TestPlan.model_validate_json(payload)
        saved = _service(ctx).save_test_plan(plan)
        return _response(
            {
                "success": True,
                "artifact": "test_plan.json",
                "test_plan": saved.model_dump(mode="json"),
            }
        )
    except (DomainArtifactError, ValidationError) as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def update_test_path_status(
    ctx: RunContextWrapper[Any],
    test_path_id: str,
    status: TestPathStatus,
) -> str:
    """Apply a valid TestPath state transition and persist the updated plan."""
    try:
        plan = _service(ctx).update_test_path_status(test_path_id, status)
        return _response(
            {
                "success": True,
                "test_path_id": test_path_id,
                "status": status,
                "test_plan": plan.model_dump(mode="json"),
            }
        )
    except DomainArtifactError as exc:
        return _error_response(exc)


@function_tool(timeout=30)
async def create_evidence(ctx: RunContextWrapper[Any], payload: str) -> str:
    """Validate and persist one Evidence item plus its manifest reference."""
    try:
        evidence = Evidence.model_validate_json(payload)
        saved = _service(ctx).save_evidence(evidence)
        return _response(
            {
                "success": True,
                "artifact": f"evidence/{saved.evidence_id}.json",
                "evidence": saved.model_dump(mode="json"),
            }
        )
    except (DomainArtifactError, ValidationError) as exc:
        return _error_response(exc)


PRODUCT_SECURITY_AGENT_TOOLS: tuple[Tool, ...] = (
    get_document_manifest,
    read_document_text,
    query_domain_artifact,
    get_product_context,
    write_product_context,
    get_attack_surface,
    write_attack_surface,
    query_test_plan,
    write_test_plan,
    update_test_path_status,
    create_evidence,
)
