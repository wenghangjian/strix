"""Structured Product Security artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


FindingStatus = Literal[
    "candidate",
    "reproduced",
    "validated",
    "impact_confirmed",
    "reportable",
    "rejected",
]

SourceBasis = Literal["documented_fact", "inference", "assumption", "unknown"]
AttackSurfaceState = Literal["declared", "observed", "undocumented", "unexpected"]
TestPathStatus = Literal[
    "candidate",
    "ready",
    "in_progress",
    "blocked",
    "completed",
    "failed",
    "skipped",
]


class TraceableContextItem(BaseModel):
    source_ref: str | None = None
    basis: SourceBasis = "unknown"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class Asset(TraceableContextItem):
    asset_id: str
    name: str
    asset_type: str | None = None


class Interface(TraceableContextItem):
    interface_id: str
    name: str
    interface_type: str | None = None
    protocol_refs: list[str] = Field(default_factory=list)


class Protocol(TraceableContextItem):
    protocol_id: str
    name: str
    transport: str | None = None
    port: int | None = None


class TrustBoundary(TraceableContextItem):
    boundary_id: str
    name: str
    description: str | None = None


class DataFlow(TraceableContextItem):
    data_flow_id: str
    source: str
    destination: str
    protocol_ref: str | None = None


class SecurityRequirement(TraceableContextItem):
    requirement_id: str
    statement: str


class ThreatHypothesis(TraceableContextItem):
    threat_id: str
    statement: str
    basis: SourceBasis


class Assumption(TraceableContextItem):
    assumption_id: str
    statement: str
    basis: SourceBasis = "assumption"


class ProductContext(BaseModel):
    schema_version: str = "1.0"
    project_id: str
    product_name: str | None = None
    product_type: str | None = None
    vendor: str | None = None
    models: list[str] = Field(default_factory=list)
    firmware_versions: list[str] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    protocols: list[Protocol] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    security_requirements: list[SecurityRequirement] = Field(default_factory=list)
    threats: list[ThreatHypothesis] = Field(default_factory=list)
    assumptions: list[Assumption] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class DocumentArtifact(BaseModel):
    schema_version: str = "1.0"
    document_id: str
    source_path: str
    file_name: str
    content_type: str
    size_bytes: int
    sha256: str
    extracted_text_path: str


class DocumentManifest(BaseModel):
    schema_version: str = "1.0"
    documents: list[DocumentArtifact] = Field(default_factory=list)


class AttackSurfaceEntry(BaseModel):
    surface_id: str
    name: str
    category: str
    state: AttackSurfaceState
    asset_refs: list[str] = Field(default_factory=list)
    interface_refs: list[str] = Field(default_factory=list)
    protocol_refs: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class AttackSurface(BaseModel):
    schema_version: str = "1.0"
    project_id: str
    entries: list[AttackSurfaceEntry] = Field(default_factory=list)


class TestStep(BaseModel):
    step_id: str
    description: str
    expected_result: str | None = None


class TestPath(BaseModel):
    schema_version: str = "1.0"
    test_path_id: str
    title: str
    objective: str
    source_refs: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    threat_refs: list[str] = Field(default_factory=list)
    requirement_refs: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[TestStep] = Field(default_factory=list)
    expected_security_control: str | None = None
    success_condition: str
    risk_level: str
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_role: str
    depends_on: list[str] = Field(default_factory=list)
    parallelizable: bool = False
    requires_approval: bool = False
    status: TestPathStatus = "candidate"


class TestPlan(BaseModel):
    schema_version: str = "1.0"
    project_id: str
    test_paths: list[TestPath] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class Evidence(BaseModel):
    schema_version: str = "1.0"
    evidence_id: str
    evidence_type: str
    source: str
    command: str | None = None
    request: str | None = None
    response: str | None = None
    file_path: str | None = None
    sha256: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    agent_id: str
    test_path_id: str | None = None


class EvidenceManifest(BaseModel):
    schema_version: str = "1.0"
    evidence_refs: list[str] = Field(default_factory=list)


class DomainFinding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str
    status: FindingStatus = "candidate"
    product_asset_refs: list[str] = Field(default_factory=list)
    test_path_id: str
    prerequisites: list[str] = Field(default_factory=list)
    test_steps: list[TestStep] = Field(default_factory=list)
    positive_result: str | None = None
    negative_control: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    impact: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    cwe: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    remediation: str | None = None
    validation_agent_id: str | None = None
