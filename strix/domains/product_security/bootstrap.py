"""Bootstrap Product Security domain runtime state."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.documents.ingestion import ingest_documents
from strix.domains.product_security.firmware.access import FirmwareAccessIssuer
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.ingestion import ingest_firmware_inputs
from strix.domains.product_security.firmware.repository import FirmwareRepository
from strix.domains.product_security.firmware.service import FirmwareAnalysisService
from strix.domains.product_security.firmware.tools import (
    FIRMWARE_ROLE_TOOLS,
    FIRMWARE_ROOT_TOOLS,
)
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
    root_tools: tuple[Tool, ...]
    role_tools: tuple[Tool, ...]
    firmware_repository: FirmwareRepository | None
    firmware_service: FirmwareAnalysisService | None
    firmware_access_issuer: FirmwareAccessIssuer | None

    @property
    def agent_tools(self) -> tuple[Tool, ...]:
        """Backward-compatible alias for role-scoped tools."""
        return self.role_tools


def enable_product_security_domain(
    config: ProductSecurityConfig,
    run_dir: Path,
    *,
    scan_id: str | None = None,
    resume: bool = False,
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
            root_tools=(),
            role_tools=(),
            firmware_repository=None,
            firmware_service=None,
            firmware_access_issuer=None,
        )

    skill_dir = Path(__file__).parent / "skills"
    register_skill_dir(skill_dir)
    trusted_scan_id = scan_id or run_dir.name
    firmware_repository = FirmwareRepository(run_dir)
    firmware_repository.initialize()
    firmware_inputs = firmware_repository.list_inputs(scan_id=trusted_scan_id)
    if resume and firmware_inputs:
        for item in firmware_inputs:
            if not firmware_repository.verify_blob(item.sha256):
                raise FirmwareDomainError(
                    "FIRMWARE_BLOB_INTEGRITY_FAILED",
                    f"Stored firmware input '{item.input_artifact_id}' failed verification.",
                    retryable=False,
                )
    else:
        ingest_firmware_inputs(
            config.artifacts,
            firmware_repository,
            scan_id=trusted_scan_id,
            max_input_bytes=config.firmware_max_input_bytes,
        )
        firmware_inputs = firmware_repository.list_inputs(scan_id=trusted_scan_id)
    firmware_service = FirmwareAnalysisService(
        firmware_repository,
        scan_id=trusted_scan_id,
    )
    firmware_access_issuer = FirmwareAccessIssuer(
        scan_id=trusted_scan_id,
        allowed_input_artifact_ids={item.input_artifact_id for item in firmware_inputs},
    )
    return ProductSecurityRuntime(
        enabled=True,
        config=config,
        artifact_repository=repository,
        role_registry=registry,
        skill_dir=skill_dir,
        root_tools=(*PRODUCT_SECURITY_AGENT_TOOLS, *FIRMWARE_ROOT_TOOLS),
        role_tools=(*PRODUCT_SECURITY_AGENT_TOOLS, *FIRMWARE_ROLE_TOOLS),
        firmware_repository=firmware_repository,
        firmware_service=firmware_service,
        firmware_access_issuer=firmware_access_issuer,
    )


def ingest_configured_documents(runtime: ProductSecurityRuntime) -> DocumentManifest | None:
    if not runtime.enabled or not runtime.config.documents:
        return None
    return ingest_documents(runtime.config.documents, runtime.artifact_repository)
