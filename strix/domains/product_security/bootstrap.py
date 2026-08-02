"""Bootstrap Product Security domain runtime state."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.documents.ingestion import ingest_documents
from strix.domains.product_security.roles.registry import RoleRegistry, default_role_registry
from strix.domains.product_security.tools import PRODUCT_SECURITY_AGENT_TOOLS
from strix.skills import register_skill_dir


if TYPE_CHECKING:
    from agents.tool import Tool

    from strix.domains.product_security.artifacts.models import DocumentManifest
    from strix.domains.product_security.config import ProductSecurityConfig


@dataclass(frozen=True)
class ProductSecurityRuntime:
    enabled: bool
    config: ProductSecurityConfig
    artifact_repository: ArtifactRepository
    role_registry: RoleRegistry
    skill_dir: Path | None
    agent_tools: tuple[Tool, ...]


def enable_product_security_domain(
    config: ProductSecurityConfig,
    run_dir: Path,
) -> ProductSecurityRuntime:
    repository = ArtifactRepository(run_dir)
    registry = default_role_registry()
    if not config.enabled:
        return ProductSecurityRuntime(
            enabled=False,
            config=config,
            artifact_repository=repository,
            role_registry=registry,
            skill_dir=None,
            agent_tools=(),
        )

    skill_dir = Path(__file__).parent / "skills"
    register_skill_dir(skill_dir)
    return ProductSecurityRuntime(
        enabled=True,
        config=config,
        artifact_repository=repository,
        role_registry=registry,
        skill_dir=skill_dir,
        agent_tools=PRODUCT_SECURITY_AGENT_TOOLS,
    )


def ingest_configured_documents(runtime: ProductSecurityRuntime) -> DocumentManifest | None:
    if not runtime.enabled or not runtime.config.documents:
        return None
    return ingest_documents(runtime.config.documents, runtime.artifact_repository)
