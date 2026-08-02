# Firmware Analysis Repository Adaptation

## Authority

- `design.md` is the product-level firmware analysis design.
- `docs/superpowers/specs/2026-08-02-product-security-phase-3-firmware-design.md` is the worker security and format contract.
- The live Strix architecture remains authoritative where either document assumes an extension point that does not exist.

## Existing Foundation

Phases 0-2 already provide the opt-in Product Security profile, role registry, role-aware child creation, run-scoped tools, atomic JSON artifacts, document ingestion, Product Context, Attack Surface, Test Plan, Evidence, and agent metadata resume.

The firmware implementation extends these components; it does not replace `run_strix_scan`, `AgentCoordinator`, SDK sessions, child spawning, or the normal scan sandbox.

## Required Adaptations

### Tool Exposure

`ProductSecurityRuntime` currently exposes one tool tuple to both Root and children. P1 splits it into:

- `root_tools`: existing domain tools plus redacted firmware summaries.
- `role_tools`: the complete Product Security tool set filtered by `RoleProfile.allowed_tool_names`.

Firmware execution tools are absent from Root construction. Every tool still performs server-side authorization because tool visibility is not an authorization boundary.

### Trusted Agent Identity

Coordinator metadata is persisted for display and resume, but does not grant access. When a child starts or respawns, trusted runner code resolves its `RoleProfile` and creates a `FirmwareAccessContext` containing the live scan ID, child ID, role ID, permitted input artifact IDs, and permissions. Model arguments and restored JSON cannot construct or expand this context.

### Firmware Storage

Existing `ArtifactRepository` remains responsible for small Product Security JSON artifacts. A dedicated `FirmwareRepository` owns `domain/firmware/firmware.db`, content-addressed blobs, exports, and recovery. It uses the same run directory but does not overload the JSON repository with large binary content.

SQLite metadata and filesystem blobs use a recoverable commit state machine because they cannot share an atomic transaction. Analysis exports are bounded derived views, not authoritative state.

### Ingestion

Configured `artifacts` are ingested before Agent execution. The importer opens each source once with no-follow semantics, validates the opened descriptor as a regular file, streams hash and copy from that descriptor, rechecks descriptor metadata, then atomically registers an immutable input artifact. Agents receive IDs and labels only.

### Candidate Findings

Firmware candidates remain separate from `DomainFinding`. P5 validation handoff creates a formal `DomainFinding` only after reproduction; existing Product Security finding states remain backward compatible.

## Delivery Slices

1. P1a: models, immutable ingestion, trusted access context, Root/role tool split.
2. P1b: SQLite migrations, CAS blobs, recovery, resume-safe query service.
3. P2a: restricted worker, host verifier, TAR/ZIP.
4. P2b: Intel HEX/S-record and MBR/GPT.
5. P2c: SquashFS and EXT2/3/4.
6. P3: Firmware Agent, rules, evidence grades, coverage, hints, and recipes.
7. P4-P5: binary triage, candidate validation handoff, reporting, and Viewer.

P3 is the first useful internal firmware-analysis milestone. P5 is the first production milestone.

## Ubuntu Verification Environment

All verification runs on Ubuntu 22.04 amd64. The host has Docker with AppArmor, seccomp, and cgroup namespace support, 15 GiB RAM, and sufficient disk for the 4 GiB one-shot worker limit. Deployment uses the Git checkout under `/srv/penoops/repository`; the earlier copied tree under `/srv/penoops/strix` is retained only as historical validation output and is not release evidence.

P0 baseline at commit `f8f9fba` completed on 2026-08-02: `627 passed` in 238.73 seconds. The only output was two existing Pydantic instance-level `model_fields` deprecation warnings in `strix/config/loader.py`.
