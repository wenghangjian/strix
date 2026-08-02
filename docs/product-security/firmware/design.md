# Strix Firmware Analysis Agent — Pragmatic Optimized Design

**Document type:** Implementation-oriented design specification  
**Target project:** Strix Product Security Domain Pack  
**Version:** 2.0 — Pragmatic optimized edition  
**Date:** 2026-08-02  
**Status:** Recommended implementation baseline  
**Relationship to previous documents:** This document consolidates and optimizes the existing Phase 3 firmware worker design and the supplementary Firmware Analysis Agent design. It preserves their security boundaries, but narrows several ambitious extensions so the system can be implemented incrementally without rewriting Strix core.

---

## 1. Executive decision

The recommended design is:

```text
Strix native Root Agent and AgentCoordinator
                ↓
Firmware Analysis Agent
                ↓
Typed firmware tools
                ↓
Firmware Analysis Service
                ↓
Restricted one-shot worker containers
                ↓
SQLite metadata store + content-addressed blob store
                ↓
Planner hints / validation recipes / candidate findings
```

The system should be built as a **safe firmware-analysis subsystem integrated into Strix**, not as a new orchestration framework and not as a free-form shell agent.

The first useful release must accomplish five things well:

1. safely ingest and unpack untrusted firmware;
2. create a verified and resume-safe artifact inventory;
3. identify services, credentials, update components, protocols and important binaries;
4. generate traceable test suggestions and candidate findings without overstating certainty;
5. hand off dynamic validation to existing or future Product Security agents.

The first release should **not** attempt to deliver:

- a full firmware knowledge graph platform;
- fleet-wide product intelligence;
- whole-program decompilation;
- automatic full-system emulation;
- automatic exploit generation;
- arbitrary raw NAND geometry inference;
- complete support for every IoT filesystem;
- a second scheduler parallel to Strix.

---

## 2. Why this optimized version

The earlier design has a strong security foundation, but some proposed extensions would substantially increase implementation cost and architectural risk:

| Proposed capability | Value | Cost/risk | Optimized decision |
|---|---:|---:|---|
| Dedicated one-shot worker | Very high | Medium | Implement now |
| Host-side verification | Very high | Medium | Implement now |
| Typed tools | Very high | Medium | Implement now |
| SQLite metadata storage | High | Medium | Implement now |
| Content-addressed blobs | High | Medium | Implement now |
| Evidence grading and coverage claims | High | Low | Implement now |
| Rule-based planner hints | High | Medium | Implement now |
| Candidate finding lifecycle | High | Medium | Implement now |
| Basic ELF inspection | High | Medium | Implement now |
| Bounded disassembly | Medium-high | Medium | Implement now |
| Ghidra selected-function decompilation | High | High | Optional second milestone |
| Full evidence graph | High | High | Implement graph-lite only |
| Full call-graph reachability analysis | High | High | Defer |
| Firmware version diff | High | Medium | Second release |
| Fleet-wide secret correlation | High | High | Defer |
| QEMU/full-system emulation | High | Very high | Defer |
| UBI/JFFS2/YAFFS/raw NAND coverage | High for IoT/OT | High | Add gradually after MVP |

This design therefore follows:

```text
Strong isolation
+ deterministic analysis
+ structured evidence
+ limited Agent reasoning
+ incremental domain expansion
```

---

## 3. Goals

### 3.1 Functional goals

The Firmware Analysis Agent must be able to:

- accept one or more immutable firmware artifacts;
- run or resume deterministic offline analysis;
- recognize supported containers, partitions and filesystems;
- safely extract regular files;
- inventory binaries, scripts, configurations, credentials, certificates and packages;
- identify likely startup services and remotely exposed components;
- identify likely update, authentication, cryptographic and protocol-related components;
- rank binaries for further inspection;
- perform bounded metadata inspection and optional disassembly;
- create evidence-backed planner hints;
- create candidate findings requiring validation;
- produce structured validation recipes for other agents;
- report coverage, unsupported content and analysis limitations.

### 3.2 Security goals

The implementation must ensure:

- imported firmware is never executed;
- extracted scripts and programs are never used as commands;
- the normal Strix scan sandbox does not receive firmware as a host mount;
- parsers run in dedicated restricted containers;
- worker output is treated as untrusted;
- paths from firmware are metadata, never storage paths or executable paths;
- sensitive values are not exposed to the LLM by default;
- static evidence cannot directly become a validated vulnerability;
- all sensitive operations are authorized server-side;
- normal Strix behavior is unchanged when Product Security is disabled.

### 3.3 Non-goals for the first release

The first release does not include:

- automatic firmware modification or repacking;
- device flashing;
- JTAG/SWD;
- hardware probing;
- exploit generation;
- automatic CVE exploitability conclusions;
- execution or emulation of firmware binaries;
- whole-image Ghidra analysis;
- multi-tenant fleet correlation;
- graph database deployment;
- automatic raw NAND/OOB geometry guessing;
- support for encrypted vendor formats without explicit adapters.

---

## 4. Core architecture

```text
┌───────────────────────────────────────────────────────────┐
│ Strix CLI / TUI / Viewer                                  │
└────────────────────────────┬──────────────────────────────┘
                             ↓
┌───────────────────────────────────────────────────────────┐
│ Strix Scan Runner and Root Agent                          │
│ - native scan lifecycle                                   │
│ - native budget and resume                                │
│ - native dynamic child creation                           │
└────────────────────────────┬──────────────────────────────┘
                             ↓
┌───────────────────────────────────────────────────────────┐
│ Firmware Analysis Agent                                   │
│ - understands product context                             │
│ - selects typed analysis actions                          │
│ - creates hypotheses, hints and validation recipes        │
│ - never directly accesses arbitrary host paths            │
└────────────────────────────┬──────────────────────────────┘
                             ↓
┌───────────────────────────────────────────────────────────┐
│ Firmware Analysis Service                                 │
│ - authorization                                           │
│ - job lifecycle                                           │
│ - artifact queries                                        │
│ - rule execution                                          │
│ - candidate/hint/recipe persistence                       │
│ - resume and dedupe                                       │
└───────────────┬───────────────────────────┬───────────────┘
                ↓                           ↓
┌─────────────────────────────┐  ┌──────────────────────────┐
│ Firmware Worker             │  │ Binary Inspection Worker │
│ - format validation         │  │ - ELF metadata           │
│ - partition/filesystem      │  │ - imports/exports        │
│ - safe extraction           │  │ - bounded disassembly    │
│ - file inventory            │  │ - optional Ghidra later  │
└───────────────┬─────────────┘  └────────────┬─────────────┘
                └───────────────┬─────────────┘
                                ↓
┌───────────────────────────────────────────────────────────┐
│ Host Verifier                                             │
│ - schema/range/count validation                           │
│ - no-follow copy                                          │
│ - SHA-256 recomputation                                   │
│ - atomic commit                                           │
└────────────────────────────┬──────────────────────────────┘
                             ↓
┌───────────────────────────────────────────────────────────┐
│ Firmware Repository                                       │
│ - SQLite metadata database                                │
│ - content-addressed blob store                            │
│ - bounded JSON exports                                    │
│ - evidence and audit records                              │
└───────────────────────────────────────────────────────────┘
```

---

## 5. Preserve Strix native core

The following components remain authoritative:

- `strix/core/runner.py`;
- `AgentCoordinator`;
- native Agent SDK sessions;
- native child spawning;
- native Agent graph and messages;
- native budget lifecycle;
- native scan resume;
- native reporting pipeline;
- native Skill loading;
- native Sandbox runtime abstraction.

No firmware-specific scheduler is introduced.

The domain extension may add:

- a firmware role profile;
- role-specific Agent tools;
- trusted runtime access context;
- domain artifacts;
- Product Security root Skill behavior;
- minimal Viewer data adapters.

It must not replace:

```text
Root Agent
→ create_agent
→ spawn_child_agent
→ AgentCoordinator
→ run_agent_loop
```

---

## 6. Agent role design

### 6.1 Role profile

```python
RoleProfile(
    role_id="firmware_analyst",
    display_name="Firmware Analysis Agent",
    description=(
        "Performs offline, evidence-driven firmware analysis and creates "
        "traceable security hypotheses and validation tasks."
    ),
    skills=[
        "product_security/firmware_analysis",
        "product_security/firmware_triage",
        "product_security/firmware_handoff",
    ],
    risk_ceiling="L1",
    inherit_context=True,
)
```

### 6.2 Tool exposure

Do not register firmware execution tools globally for every Agent.

The Firmware Analysis Agent receives only the tools in its profile:

```text
get_firmware_job
get_firmware_summary
start_firmware_analysis
list_firmware_artifacts
get_firmware_artifact_metadata
search_firmware_paths
search_firmware_strings
list_firmware_binaries
inspect_firmware_binary
disassemble_firmware_binary
run_firmware_rules
create_firmware_planner_hint
create_firmware_validation_recipe
create_firmware_candidate_finding
request_firmware_geometry
list_firmware_evidence
finish_firmware_analysis
```

The Root Agent receives only redacted summary tools:

```text
list_firmware_jobs
get_firmware_summary
list_firmware_planner_hints
list_firmware_candidates
```

### 6.3 Agent responsibilities

The Firmware Analysis Agent must:

1. read product context and scope;
2. select an imported firmware artifact;
3. start or resume deterministic analysis;
4. review completeness and limitations;
5. query verified artifacts through typed tools;
6. run relevant rule packs;
7. prioritize relevant binaries;
8. request bounded deeper inspection only where justified;
9. create planner hints and validation recipes;
10. create candidate findings only with explicit missing validation;
11. finish with coverage and limitation statements.

The Agent must not:

- execute arbitrary shell commands on extracted content;
- request direct host path access;
- execute or source extracted scripts;
- mount filesystems;
- use loop devices;
- expose full secrets in conversation;
- guess NAND geometry from weak evidence;
- report package strings as proof of an exploitable CVE;
- declare absence of a security control without coverage qualification;
- directly change a finding to `validated`.

---

## 7. Trusted access context

A full platform-wide capability framework is valuable but too invasive for the first implementation.

Use a firmware-scoped trusted access context created by the Scan Runner:

```python
class FirmwareAccessContext(BaseModel):
    scan_id: str
    agent_id: str
    role_id: str

    allowed_input_artifact_ids: frozenset[str]
    permissions: frozenset["FirmwarePermission"]
    access_profile: str

    issued_by: Literal["scan_runner"]
```

```python
class FirmwarePermission(StrEnum):
    SUMMARY_READ = "firmware.summary.read"
    METADATA_READ = "firmware.metadata.read"
    CONTENT_PREVIEW = "firmware.content.preview"
    SECRET_FINGERPRINT_READ = "firmware.secret.fingerprint.read"
    SECRET_REVEAL = "firmware.secret.reveal"
    WORKER_EXECUTE = "firmware.worker.execute"
    BINARY_INSPECT = "firmware.binary.inspect"
    BINARY_DISASSEMBLE = "firmware.binary.disassemble"
    BINARY_DECOMPILE = "firmware.binary.decompile"
    HINT_CREATE = "firmware.hint.create"
    RECIPE_CREATE = "firmware.recipe.create"
    CANDIDATE_CREATE = "firmware.candidate.create"
```

Important constraints:

- it is inserted into runtime context by trusted Python code;
- it is never accepted as a model/tool argument;
- metadata restored from `agents.json` does not independently grant access;
- every tool verifies `scan_id`, `agent_id`, permission and `analysis_id`;
- analysis access is derived server-side from an allowed input artifact and its scan;
- cross-scan reads are denied;
- `firmware.candidate.validate` is intentionally absent.

This gives most of the benefit of capability authorization without requiring an immediate redesign of every Strix tool.

---

## 8. Ingestion model

### 8.1 Do not expose host paths to the Agent

The CLI or control plane may accept:

```bash
strix --artifact ./firmware.bin
```

But before any Agent starts, the control plane must:

1. open the source once with no-follow behavior and copy only from that descriptor;
2. require a regular file;
3. enforce input size;
4. compare descriptor metadata before and after the copy, and compute SHA-256 while streaming;
5. copy it to the controlled ingestion store;
6. create an immutable `FirmwareInputArtifact`;
7. pass only the generated artifact ID to Agents.

Agent-facing tools use:

```python
start_firmware_analysis(
    input_artifact_id="fw_input_...",
    geometry_contract=None,
)
```

They do not accept:

```python
artifact_path="/host/path/firmware.bin"
```

### 8.2 Input model

```python
class FirmwareInputArtifact(BaseModel):
    schema_version: str
    input_artifact_id: str
    scan_id: str
    project_id: str | None

    sha256: str
    size_bytes: int
    storage_name: str

    label: str | None
    source_type: Literal["cli", "upload", "connector", "fixture"]
    source_description: str | None

    geometry_contract: "FirmwareGeometryContract | None"
    created_at: datetime
```

### 8.3 Geometry contract

```python
class FirmwareGeometryContract(BaseModel):
    page_size: int | None = None
    oob_size: int | None = None
    pages_per_erase_block: int | None = None
    chip_count: int | None = None
    interleave: int | None = None
    includes_oob: bool | None = None
    byte_order: Literal["little", "big"] | None = None
    base_address: int | None = None
    architecture: str | None = None
    expected_filesystem: str | None = None
    source: Literal["user", "datasheet", "known_profile"]
```

The system may validate geometry but must not silently invent it.

---

## 9. Worker isolation

Retain the existing strong worker model.

### 9.1 Firmware worker requirements

Each parsing job runs in a dedicated one-shot container with:

- `network=none`;
- no host mounts;
- no devices;
- all Linux capabilities dropped;
- `no-new-privileges`;
- non-root user;
- read-only root filesystem;
- bounded noexec work storage;
- PID, memory, CPU and time limits;
- pinned image digest;
- pinned tool versions;
- seccomp restrictions;
- no shell and no package manager where practical;
- audited absolute-path command dispatch;
- argument arrays, never shell interpolation.

The worker receives one immutable input and emits:

- one JSON manifest;
- generated regular-file blobs;
- bounded diagnostic data.

### 9.2 Host verification

The host must treat all worker output as untrusted and:

- reject unknown files;
- reject non-generated blob names;
- use no-follow operations;
- verify count and size limits;
- recompute every SHA-256;
- validate node parentage and byte ranges;
- validate schemas;
- reject links and special objects;
- atomically commit or reject the complete staging result.

### 9.3 Worker status

Use:

```text
complete
partial
failed
rejected
detected_unsupported
not_applicable
unclassified
```

Do not reduce these states to a boolean.

---

## 10. Supported format roadmap

### 10.1 Release 1 formats

Implement and stabilize:

- TAR;
- ZIP;
- SquashFS;
- EXT2/3/4;
- MBR;
- GPT;
- Intel HEX;
- Motorola S-record;
- ELF metadata inspection.

These provide a practical MVP across Linux firmware, disk images and MCU record formats.

### 10.2 Release 2 IoT formats

Add adapters one at a time:

1. uImage;
2. FIT image;
3. CramFS;
4. UBI/UBIFS;
5. JFFS2.

Each adapter requires:

- strict preflight;
- positive fixtures;
- malformed fixtures;
- size/range tests;
- verifier postconditions;
- resume-key versioning.

### 10.3 Later formats

Defer until geometry and fixtures exist:

- YAFFS;
- raw NAND with OOB;
- vendor-encrypted update packages;
- VxWorks component extraction;
- proprietary RTOS filesystems;
- bare-metal image segmentation.

For raw NAND, weak UBI/JFFS2/OOB observations may generate `request_firmware_geometry`, but not automatic extraction.

`request_firmware_geometry` creates a structured blocker containing missing fields and supporting observations. User-supplied geometry creates a new immutable input revision and analysis key; it never mutates an existing completed analysis in place.

---

## 11. Repository design

### 11.1 Storage choice

Use:

```text
SQLite metadata database
+
content-addressed blob store
+
bounded JSON export
```

This is more robust than using JSONL as the primary mutable state, while remaining simple enough for a local Strix deployment.

### 11.2 Layout

```text
strix_runs/<scan-id>/domain/firmware/
├── firmware.db
├── inputs/
│   └── <input-artifact-id>.json
├── blobs/
│   └── sha256/
│       └── ab/
│           └── <generated-blob-name>
├── evidence/
│   └── raw/
├── exports/
│   ├── summary.json
│   ├── inventory.json
│   ├── planner_hints.json
│   ├── validation_recipes.json
│   └── candidates.json
├── staging/
└── logs/
```

### 11.3 SQLite settings

Use:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
```

Repository writes must use explicit transactions.

Schema changes use numbered migrations.

SQLite and the blob filesystem do not form one transaction. Commits therefore use a recoverable state machine:

```text
staging
→ blobs_committed
→ metadata_committed
→ complete
```

Blob promotion uses same-filesystem atomic renames. Startup recovery removes abandoned staging, verifies promoted hashes, and either completes or rolls back non-terminal jobs before they can be resumed.

### 11.4 Core tables

Minimum tables:

```text
firmware_input
firmware_analysis
blob
artifact_node
artifact_path
analysis_attempt
observation
evidence
planner_hint
validation_recipe
candidate_finding
binary
binary_inspection
secret_candidate
service_candidate
package_candidate
relation
audit_event
```

### 11.5 Graph-lite relations

Do not deploy a graph database in the first implementation.

Use a typed `relation` table:

```python
class FirmwareRelation(BaseModel):
    relation_id: str
    analysis_id: str

    source_type: str
    source_id: str
    relation_type: str
    target_type: str
    target_id: str

    evidence_refs: list[str]
    evidence_grade: "EvidenceGrade"
```

Initial relation types:

```text
contains
starts
executes
references
loads
binds_to
uses_credential
uses_certificate
updates
implements_protocol
derived_from
supports
contradicts
```

This enables useful relation queries without implementing a general graph engine.

---

## 12. Evidence and coverage model

### 12.1 Evidence grade

Use categorical evidence grades for state decisions:

```python
class EvidenceGrade(StrEnum):
    A = "A"  # deterministic parsed fact verified by host verifier
    B = "B"  # strong relation supported by multiple verified artifacts
    C = "C"  # static semantic inference
    D = "D"  # weak indicator or single string/signature
    U = "U"  # unknown or insufficient coverage
```

Rules:

- D-level evidence creates only a review hint;
- C-level evidence may create a candidate finding;
- A/B evidence is required for strong planner hints;
- a validated vulnerability still requires corroboration or dynamic evidence;
- confidence float may be used for ranking, not lifecycle authorization.

### 12.2 Coverage claim

```python
class CoverageClaim(BaseModel):
    scope: str
    expected_units: int | None
    analyzed_units: int
    unsupported_units: int
    failed_units: int

    level: Literal[
        "complete",
        "substantial",
        "partial",
        "minimal",
        "unknown",
    ]

    limitations: list[str]
```

Examples:

- filesystem extraction coverage;
- startup configuration coverage;
- executable metadata coverage;
- update component coverage;
- decompilation coverage.

The Agent must attach relevant coverage claims to conclusions based on absence:

```text
No reachable signature-verification path was found
within the analyzed update binaries.

Coverage: partial.
One architecture was unsupported.
This is not proof that signature verification is absent.
```

---

## 13. Domain models

### 13.1 Firmware analysis summary

```python
class FirmwareAnalysisSummary(BaseModel):
    schema_version: str
    analysis_id: str
    input_artifact_id: str

    status: str
    detected_formats: list[str]
    selected_adapters: list[str]

    partition_count: int
    filesystem_count: int
    regular_file_count: int
    executable_count: int

    service_candidate_count: int
    secret_candidate_count: int
    update_component_count: int
    protocol_candidate_count: int

    coverage: list[CoverageClaim]
    limitations: list[str]
    evidence_refs: list[str]

    started_at: datetime
    completed_at: datetime | None
```

### 13.2 Observation

```python
class FirmwareObservation(BaseModel):
    schema_version: str
    observation_id: str
    analysis_id: str
    rule_id: str

    category: str
    title: str
    description: str

    fact_type: Literal["observed", "derived", "hypothesis", "unknown"]
    evidence_grade: EvidenceGrade
    confidence: float

    artifact_node_ids: list[str]
    evidence_refs: list[str]
    coverage_refs: list[str]

    sensitive: bool
    created_at: datetime
```

Rule engines normally create `observed` or `derived`.
The Agent creates `hypothesis`.

### 13.3 Planner hint

```python
class FirmwarePlannerHint(BaseModel):
    schema_version: str
    hint_id: str
    analysis_id: str

    category: Literal[
        "attack_surface",
        "authentication",
        "authorization",
        "credential",
        "cryptography",
        "update_security",
        "protocol_security",
        "service_exposure",
        "hardening",
        "dynamic_validation",
        "manual_review",
    ]

    title: str
    rationale: str

    source_artifact_ids: list[str]
    evidence_refs: list[str]
    relation_refs: list[str]

    evidence_grade: EvidenceGrade
    confidence: float

    suggested_role: str
    suggested_test_type: str
    prerequisites: list[str]
    expected_control: str | None

    status: Literal[
        "proposed",
        "accepted",
        "scheduled",
        "completed",
        "dismissed",
    ]
```

### 13.4 Validation recipe

A validation recipe is the main bridge between static analysis and other Agents.

```python
class FirmwareValidationRecipe(BaseModel):
    schema_version: str
    recipe_id: str
    analysis_id: str

    title: str
    objective: str
    target_component: str

    source_artifact_ids: list[str]
    evidence_refs: list[str]
    hypothesis: str

    prerequisites: list[str]
    setup_steps: list["TypedValidationStep"]
    execution_steps: list["TypedValidationStep"]
    positive_control: list["TypedValidationStep"]
    negative_control: list["TypedValidationStep"]
    expected_observations: list[str]
    cleanup_steps: list["TypedValidationStep"]

    required_agent_role: str
    risk_level: Literal["L0", "L1", "L2", "L3", "L4", "L5"]
    requires_approval: bool

    status: Literal[
        "draft",
        "approved",
        "scheduled",
        "running",
        "completed",
        "rejected",
    ]
```

Release 1 supports template-generated steps only.
The Agent may fill parameters but may not invent arbitrary executable commands.

### 13.5 Candidate finding

```python
class FirmwareCandidateFinding(BaseModel):
    schema_version: str
    candidate_id: str
    analysis_id: str

    title: str
    category: str
    hypothesis: str

    evidence_grade: EvidenceGrade
    confidence: float
    severity_hint: str | None

    observed_facts: list[str]
    assumptions: list[str]
    missing_validation: list[str]

    source_artifact_ids: list[str]
    evidence_refs: list[str]
    coverage_refs: list[str]
    validation_recipe_ids: list[str]

    status: Literal[
        "candidate",
        "queued_for_validation",
        "reproduced",
        "validated",
        "rejected",
        "deferred",
    ]

    created_by_agent_id: str
    validated_by_agent_id: str | None
```

The Firmware Analysis Agent may only create:

```text
candidate
queued_for_validation
deferred
```

Only the Validator may set:

```text
reproduced
validated
rejected
```

`FirmwareCandidateFinding` remains separate from the existing Product Security `DomainFinding`. Validation handoff promotes a reproduced candidate into a `DomainFinding`; firmware-specific draft states do not change the existing finding lifecycle.

---

## 14. Rule engine

### 14.1 Purpose

The rule engine converts verified artifacts into observations and relations.

It must not directly create validated findings.

### 14.2 Initial rule packs

#### `firmware.base_inventory.v1`

- executable inventory;
- library inventory;
- scripts;
- configuration files;
- certificates;
- private-key candidates;
- package manifests;
- web roots;
- CGI/FastCGI handlers.

#### `firmware.startup_services.v1`

- SysV init scripts;
- systemd units;
- inetd/xinetd;
- rc.local;
- cron;
- shell startup chains;
- common embedded service launchers.

Outputs:

```text
startup configuration
→ starts
→ executable
→ references
→ configuration
```

#### `firmware.authentication.v1`

- passwd/shadow metadata;
- default-looking accounts;
- SSH authorized keys;
- Dropbear/OpenSSH settings;
- web authentication configs;
- hard-coded username/password indicators;
- empty or locked account status.

#### `firmware.update_security.v1`

- update scripts;
- upload handlers;
- package manifest checks;
- checksum logic;
- signature-verification indicators;
- trust anchor references;
- rollback/version checks;
- flash-write utilities.

Absence of a detected signature check is never a standalone finding.

#### `firmware.protocols.v1`

- Modbus;
- MQTT;
- OPC UA;
- IEC 60870-5-104;
- DNP3;
- BACnet;
- UMAS;
- CAN-related utilities;
- vendor protocol strings and ports.

Protocol identification based only on a single string is Evidence Grade D.

#### `firmware.crypto_material.v1`

- certificates;
- private keys;
- symmetric-key candidates;
- shared key references;
- insecure algorithm configuration;
- trust stores.

### 14.3 Rule output requirements

Every rule output must include:

- stable `rule_id`;
- rule version;
- source artifact IDs;
- evidence references;
- evidence grade;
- coverage reference;
- deterministic dedupe key;
- redaction status.

---

## 15. Secret handling

### 15.1 Default behavior

Do not display partial plaintext secrets by default.

Agent-visible output contains:

```text
type
length
format/algorithm
SHA-256 fingerprint
source artifact ID
occurrence count
sensitivity
```

Example:

```json
{
  "secret_type": "private_key",
  "algorithm": "RSA",
  "key_bits": 2048,
  "fingerprint": "sha256:...",
  "source_count": 3,
  "sensitivity": "critical"
}
```

### 15.2 Secret handle

```python
class SecretHandle(BaseModel):
    secret_ref: str
    analysis_id: str
    secret_type: str
    fingerprint: str
    sensitivity: str
```

Other tools should accept `secret_ref` where possible, rather than exposing raw values to the Agent.

### 15.3 Secret reveal

Raw reveal requires:

- explicit permission;
- policy approval;
- bounded use case;
- audit record;
- no inclusion in Agent messages or normal logs.

The first release may omit raw secret reveal entirely.

---

## 16. Binary triage

### 16.1 Release 1 objective

Identify and inspect the small subset of binaries most likely to implement:

- external services;
- authentication;
- update handling;
- protocol parsing;
- cryptographic verification;
- command execution;
- privileged management.

### 16.2 Deterministic base score

Keep a transparent weighted score:

```text
+30 referenced by startup/service configuration
+25 CGI/FastCGI or web-handler relation
+25 update/upgrade relation
+20 network bind/listen indicators
+20 authentication/session indicators
+20 protocol indicators from multiple sources
+15 privileged owner/mode or setuid/setgid
+15 cryptographic verification indicators
+10 process-execution imports
+10 file-write/permission imports
+10 stripped and externally exposed candidate
+5  high-entropy executable section
```

### 16.3 Relation-aware boost

Add only lightweight relation boosts in Release 1:

```text
startup configuration → starts → binary
web handler → executes → binary
service configuration → references → binary
update script → executes → binary
protocol config → references → binary
```

Do not implement full interprocedural reachability in the MVP.

### 16.4 Limits

Default limits:

- inventory all identified binaries within repository limits;
- metadata inspection: top 100;
- bounded disassembly: top 15;
- optional Ghidra: top 3;
- selected functions per binary: 15;
- total deep inspection time: 15 minutes;
- all limits configurable and versioned.

---

## 17. Binary inspection and decompilation

### 17.1 Stage A — metadata inspection

Implement first.

Use fixed-argument pinned tools or repository parsers:

- `file`;
- `readelf`;
- `objdump`;
- `nm` where safe;
- optional PE parser;
- optional raw-binary metadata adapters.

Collect:

- architecture;
- bitness;
- endianness;
- entry point;
- sections and segments;
- imports and exports;
- dynamic dependencies;
- interpreter;
- RPATH/RUNPATH;
- PIE/NX/RELRO/canary indicators;
- symbols;
- selected strings and references where supported.

### 17.2 Stage B — bounded disassembly

Implement in the first useful release.

Allow selection by:

- entry point;
- exact symbol;
- export;
- callers of a selected import where supported;
- references to selected strings where supported;
- address validated inside an executable region.

Persist raw output as an artifact.
Return only bounded excerpts to the Agent.

### 17.3 Stage C — optional Ghidra

Do not block the MVP on Ghidra.

Add after Stages A and B are stable.

Ghidra must run in a separate one-shot container with:

- pinned digest and version;
- repository-owned analysis scripts only;
- no user-supplied scripts;
- no network;
- no mounts or devices;
- non-root;
- read-only root filesystem;
- bounded project storage;
- timeout and memory limits;
- immutable selected binary input;
- rehashed generated output;
- limited functions and output size.

### 17.4 Ghidra output

Do not return only large pseudo-C files.

Preferred structured output:

```python
class FunctionAnalysisSummary(BaseModel):
    function_id: str
    function_name: str | None
    address: int

    callers: list[str]
    callees: list[str]
    imported_calls: list[str]
    string_refs: list[str]

    source_indicators: list[str]
    security_check_indicators: list[str]
    dangerous_sink_indicators: list[str]

    pseudocode_excerpt_ref: str | None
    evidence_refs: list[str]
    interpretation_limitations: list[str]
```

Release 2 may add security-oriented profiles:

```text
auth
update
protocol
crypto
command_execution
file_upload
```

Full program slicing is deferred.

---

## 18. Hypothesis and validation templates

The Agent should use typed templates rather than unconstrained prose.

### 18.1 Shared private key

Observed:

- a verified private key exists;
- a service configuration or certificate references it.

Hypothesis:

- the identity key may be shared across devices or firmware versions.

Validation recipe:

- compare public-key fingerprints across two authorized devices or images;
- confirm service usage;
- do not expose private key material.

### 18.2 Default credential

Observed:

- default-looking account;
- hash/configuration;
- remote service startup relation.

Hypothesis:

- a default credential may allow remote access.

Validation recipe:

- confirm service exposure;
- test only within authorization scope;
- use a negative-control credential;
- record account privilege.

### 18.3 Update authenticity

Observed:

- update entry point;
- checksum indicators;
- no reachable signature verification found in analyzed coverage.

Hypothesis:

- authenticity enforcement may be absent or incomplete.

Validation recipe:

- inspect all update paths;
- locate trust anchors;
- confirm supported coverage;
- test modified packages only in a safe test environment;
- require approval for state-changing validation.

### 18.4 Protocol authorization

Observed:

- protocol service/library;
- startup or exposure configuration;
- authorization configuration not observed.

Hypothesis:

- protocol operations may be reachable without authentication.

Validation recipe:

- Attack Surface Agent confirms reachability;
- Protocol Security Agent performs read-only identification;
- state-changing tests remain disabled by default.

---

## 19. Cross-Agent integration

### 19.1 Test Planning Agent

Consumes:

- accepted planner hints;
- validation recipes;
- evidence references;
- risk level;
- prerequisites;
- expected control;
- coverage limitations.

Creates explicit Test Paths.

### 19.2 Attack Surface Agent

Receives recipes related to:

- service exposure;
- management ports;
- telnet/SSH/HTTP;
- debug endpoints;
- undocumented daemons.

### 19.3 Protocol Security Agent

Receives recipes related to:

- protocol implementation;
- expected ports;
- binary/config references;
- safe identification tests;
- authorization hypotheses.

### 19.4 Update Security Agent

May be added later.
Until then, the Test Planner can assign update recipes to a generic specialist child.

### 19.5 Vulnerability Validator

Receives:

- candidate finding;
- evidence;
- recipe;
- missing validation;
- positive and negative controls;
- coverage limitations.

The Validator alone changes candidate status to validated or rejected.

---

## 20. Firmware diff — scoped second release

Firmware comparison has high value, but should not delay the first end-to-end release.

### 20.1 Release 2 diff scope

Support comparison of two analyses for the same product/model:

- file added/removed/changed;
- service added/removed/changed;
- account/config changed;
- secret fingerprint reused/changed;
- certificate changed;
- package/version changed;
- update component changed;
- binary blob changed;
- planner hints added/removed.

### 20.2 Deferred diff scope

Defer:

- function-level binary similarity;
- call graph diff;
- semantic patch identification;
- cross-organization fleet correlation;
- vulnerability fix inference without confirmation.

### 20.3 Data model

```python
class FirmwareComparison(BaseModel):
    comparison_id: str
    baseline_analysis_id: str
    candidate_analysis_id: str

    file_changes: list["DiffRecord"]
    service_changes: list["DiffRecord"]
    secret_changes: list["DiffRecord"]
    package_changes: list["DiffRecord"]
    update_changes: list["DiffRecord"]
    binary_changes: list["DiffRecord"]

    security_regression_hints: list[str]
    evidence_refs: list[str]
```

Security regression hints remain hypotheses.

---

## 21. Resume and idempotency

### 21.1 Canonical analysis key

Hash:

- input SHA-256 and size;
- schema version;
- analysis limits;
- geometry contract;
- enabled adapters;
- worker image digest;
- seccomp/policy digest;
- tool versions;
- rule-set versions;
- binary inspection version;
- redaction policy version.

### 21.2 Resume behavior

On resume:

1. validate input and persisted blob hashes;
2. load the database and schema version;
3. reject uncommitted staging;
4. reuse successful deterministic jobs with the same key;
5. retry only retryable failed jobs;
6. restore hints, recipes and candidates;
7. restore analysis IDs into Agent metadata;
8. avoid duplicate output through deterministic keys;
9. invalidate binary/decompilation output when engine digest or profile changes.

### 21.3 Dedupe keys

Use stable keys for:

- observation: rule + normalized facts + evidence;
- relation: source + type + target + evidence;
- hint: category + test type + component + evidence;
- recipe: objective + target + evidence;
- candidate: hypothesis class + component + evidence;
- binary inspection: blob hash + tool version;
- decompilation: blob hash + engine digest + selectors.

---

## 22. Tool result envelope

All firmware tools return:

```python
class ToolResult(BaseModel, Generic[T]):
    success: bool
    error_code: str | None
    message: str
    retryable: bool
    data: T | None
    artifact_refs: list[str]
    warnings: list[str]
```

Minimum error codes:

```text
FIRMWARE_INPUT_NOT_FOUND
FIRMWARE_INPUT_TOO_LARGE
FIRMWARE_ACCESS_DENIED
FIRMWARE_WORKER_START_FAILED
FIRMWARE_WORKER_TIMEOUT
FIRMWARE_WORKER_OOM
FIRMWARE_WORKER_ENOSPC
FIRMWARE_OUTPUT_SCHEMA_INVALID
FIRMWARE_OUTPUT_HASH_MISMATCH
FIRMWARE_RANGE_INVALID
FIRMWARE_EXTRACTION_REJECTED
FIRMWARE_FORMAT_UNSUPPORTED
FIRMWARE_GEOMETRY_REQUIRED
FIRMWARE_ARTIFACT_CORRUPT
FIRMWARE_BINARY_UNSUPPORTED
FIRMWARE_INSPECTION_LIMIT_EXCEEDED
FIRMWARE_DISASSEMBLY_FAILED
FIRMWARE_DECOMPILATION_FAILED
FIRMWARE_RESUME_KEY_MISMATCH
```

Errors must not be returned as unstructured exception strings.

---

## 23. Minimal Viewer integration

Do not redesign the entire Viewer in the first implementation.

Release 1 displays:

- firmware job status;
- input hash and size;
- detected formats;
- partition/filesystem summary;
- extraction completeness;
- artifact counts;
- service/secret/update/protocol counts;
- top-ranked binaries;
- planner hints;
- validation recipes;
- candidate lifecycle;
- limitations and coverage;
- Agent role badge.

Release 2 may add:

- artifact relation view;
- firmware comparison;
- binary inspection page;
- evidence drill-down.

The Viewer must not display unrestricted secrets.

---

## 24. Recommended code organization

```text
strix/
  domains/
    product_security/
      firmware/
        __init__.py
        bootstrap.py

        access.py
        config.py
        errors.py
        models.py

        ingestion.py
        repository.py
        migrations/
          0001_initial.sql
          0002_relations.sql

        service.py
        jobs.py
        resume.py

        worker/
          container.py
          manifest.py
          verifier.py
          dispatch.py

        formats/
          base.py
          archives.py
          squashfs.py
          ext.py
          partition.py
          records.py

        rules/
          registry.py
          base_inventory.py
          startup_services.py
          authentication.py
          update_security.py
          protocols.py
          crypto_material.py

        binary/
          models.py
          ranking.py
          inspection.py
          disassembly.py
          ghidra.py

        tools/
          query.py
          execution.py
          outputs.py

        skills/
          firmware_analysis.md
          firmware_triage.md
          firmware_handoff.md
```

Tests:

```text
tests/
  domains/
    product_security/
      firmware/
        test_access.py
        test_ingestion.py
        test_repository.py
        test_resume.py
        test_worker_container.py
        test_worker_verifier.py
        test_archive_adapters.py
        test_squashfs_adapter.py
        test_ext_adapter.py
        test_partition_adapter.py
        test_record_adapter.py
        test_rules.py
        test_binary_ranking.py
        test_binary_inspection.py
        test_disassembly.py
        test_agent_tools.py
        test_validator_handoff.py
        test_e2e_firmware.py
```

---

## 25. Implementation phases

The phases below are intentionally smaller than the previous F0–F7 plan.

Each phase must result in a reviewable, testable state.

---

### Phase P0 — repository review and baseline

Tasks:

1. inspect current Strix architecture;
2. inspect any existing Product Security role/profile code;
3. map extension points;
4. run the full test suite;
5. record current CLI and resume behavior;
6. write a file-level implementation plan;
7. create a firmware threat model.

Deliverables:

```text
docs/product-security/firmware/architecture.md
docs/product-security/firmware/threat-model.md
docs/product-security/firmware/implementation-plan.md
```

Acceptance:

- no runtime behavior change;
- all existing tests pass;
- modified core files are explicitly listed;
- no unrelated refactor is proposed.

---

### Phase P1 — ingestion, access and repository

Implement:

- immutable ingestion before Agent execution;
- `FirmwareInputArtifact`;
- `FirmwareAccessContext`;
- permission checks;
- SQLite repository and migrations;
- content-addressed blob store;
- atomic staging/commit;
- summary and artifact query repository APIs.

Do not yet implement full extraction.

Acceptance:

- Agent never receives a host path;
- unauthorized roles cannot query firmware data;
- cross-scan access is denied;
- blob hashes are revalidated;
- database resume works;
- Product Security disabled behavior is unchanged.

---

### Phase P2a — worker bridge and archive baseline

Implement:

- restricted one-shot firmware worker;
- manifest;
- host verifier;
- TAR/ZIP;
- status aggregation;
- resume key;
- structured errors.

Acceptance:

- malicious archive fixtures are rejected;
- extracted content is never executed;
- no firmware host mount appears in the normal scan sandbox;
- malformed output rejects the full staging result;
- supported fixtures produce deterministic inventory;
- timeout/OOM/ENOSPC tear down cleanly;
- resume does not reuse interrupted staging.

### Phase P2b — records and partitioned images

Implement:

- Intel HEX/S-record;
- MBR/GPT;
- recursive dispatch from validated partitions and normalized segments.

Acceptance:

- checksums, control records, overlaps and large gaps are deterministic;
- GPT CRCs, backup headers, EBR chains and range arithmetic are verified;
- advisory Binwalk observations do not create required child nodes.

### Phase P2c — Linux filesystems

Implement:

- SquashFS;
- EXT2/3/4;
- filesystem completeness verification.

Acceptance:

- directory-only and truncated extraction never report complete;
- filenames, hard links, sparse files and special objects follow the worker contract;
- images are never mounted and journals are never replayed.

---

### Phase P3 — Firmware Agent and rule-based triage

Implement:

- `firmware_analyst` role;
- role-specific Skills;
- typed query tools;
- initial rule packs;
- observations;
- relations;
- evidence grades;
- coverage claims;
- planner hints;
- validation recipes;
- redaction.

Acceptance:

- Root Agent delegates firmware work;
- firmware role receives only allowed tools;
- fixture produces service/auth/update/protocol hints;
- every hint and recipe references evidence;
- weak strings do not become candidate findings;
- partial coverage is reported accurately;
- resumed analysis does not duplicate observations or hints.

This phase produces the first meaningful Agent-enabled firmware product.

---

### Phase P4 — binary triage and bounded disassembly

Implement:

- executable inventory;
- deterministic ranking;
- relation-aware boosts;
- ELF metadata inspection;
- security property extraction;
- imports/exports/dependencies;
- bounded disassembly;
- selected strings and references where supported;
- binary inspection artifacts.

Acceptance:

- important fixture binaries rank near the top;
- scoring reasons are explainable;
- no binary is executed;
- unsupported architectures are explicit;
- invalid address/function selectors are rejected;
- output, runtime and count limits are enforced.

---

### Phase P5 — candidate findings and validation handoff

Implement:

- candidate finding lifecycle;
- minimum evidence checks;
- Validator queue;
- validation recipe handoff;
- positive and negative control requirements;
- report pipeline integration;
- minimal Viewer support;
- full E2E demo.

Acceptance:

```text
firmware input
→ worker
→ verified inventory
→ Firmware Agent
→ planner hint / validation recipe
→ candidate finding
→ Validator
→ validated or rejected
→ report
```

works end-to-end.

The demo must contain:

- one candidate validated with corroborating evidence;
- one static-only candidate rejected or left pending;
- one unsupported/partial analysis surfaced as a limitation;
- resume after interruption.

This is the recommended first production milestone.

---

### Phase P6 — optional Ghidra and IoT format expansion

Implement incrementally:

- selected-function Ghidra Headless;
- uImage;
- FIT;
- CramFS;
- UBI/UBIFS;
- JFFS2.

Do not combine all adapters into one large PR.

Each adapter or engine should have its own tests and review.

Acceptance:

- only selected binaries/functions are processed;
- no scripts from firmware execute;
- Ghidra output is bounded and structured;
- each filesystem adapter passes positive and hostile fixtures;
- resume invalidates output when tool/image digest changes.

---

### Phase P7 — firmware comparison

Implement:

- two-analysis comparison;
- file/service/account/secret/package/update/binary blob diff;
- security regression hints;
- comparison Viewer page.

Acceptance:

- comparison output is deterministic;
- unchanged blob content is reused;
- secret values remain hidden;
- regression hints remain hypotheses;
- no function-level semantic diff is claimed.

---

## 26. Test strategy

### 26.1 Unit tests

Cover:

- model validation;
- permissions;
- stable IDs;
- dedupe keys;
- migrations;
- evidence grades;
- coverage claims;
- status transitions;
- redaction;
- rule output;
- scoring;
- selector validation;
- resume keys;
- error envelope.

### 26.2 Worker security tests

Prove:

- no network;
- no mount;
- no loop/device access;
- no privilege escalation;
- no namespace/ptrace/module use;
- fixed absolute-path dispatch;
- no extracted path used as a command;
- clean teardown;
- path traversal rejection;
- links and special files rejected;
- compression/logical size accounted separately;
- malformed output rejected;
- hash mismatch rejected.

### 26.3 Format tests

Cover:

- TAR/ZIP traversal, collisions, CRC, encryption, ZIP64 and dishonest sizes;
- SquashFS names, escaping, special objects and invalid pseudo-file output;
- EXT corruption, unsupported features, sparse files, hard links and non-UTF-8 names;
- GPT CRC/backup mismatch, MBR chains, overlap, truncation and overflow;
- HEX/S-record checksum, count, overlap, termination and large gaps.

### 26.4 Rule tests

Use fixtures with:

- startup services;
- default account candidates;
- test private keys;
- web handlers;
- update scripts;
- protocol indicators;
- inactive misleading configuration.

Verify:

- facts are not overstated;
- inactive config is not automatically treated as active;
- single strings remain weak evidence;
- absence conclusions include coverage.

### 26.5 Agent integration tests

Use deterministic mock model paths to verify:

- Root delegates;
- firmware role receives allowed tools only;
- Agent cannot read raw host paths;
- Agent cannot reveal secrets;
- Agent creates evidence-backed outputs;
- Agent cannot validate findings;
- resume does not duplicate work;
- unsupported states are reported accurately.

### 26.6 Quality gates

Run:

```bash
pytest
ruff check .
mypy strix
pyright
bandit -c pyproject.toml -r strix
```

Build and smoke-test:

- main package;
- firmware worker image;
- Viewer where changed;
- optional binary/Ghidra image where enabled.

---

## 27. Explicit prohibitions

The implementation must not:

- rewrite `AgentCoordinator`;
- replace dynamic child agents with a hard-coded workflow engine;
- add a second Agent graph;
- expose firmware tools to every Agent;
- accept Agent-controlled host file paths;
- mount or execute firmware content;
- use extracted filenames as storage filenames;
- invoke tools through shell interpolation;
- use unsafe generic extraction fallback;
- treat Binwalk signatures as authoritative extraction;
- guess NAND geometry;
- log or message raw secrets;
- infer exploitable CVEs from package strings alone;
- promote static observations directly to validated findings;
- implement full emulation in the MVP;
- create a graph-database dependency in the MVP;
- combine all formats and decompilation work into one PR;
- break ordinary Strix scans when Product Security is disabled.

---

## 28. PR structure

Recommended PR sequence:

```text
PR 1 — Firmware ingestion, access context and repository
PR 2a — Restricted worker, verifier and TAR/ZIP
PR 2b — Intel HEX/S-record and MBR/GPT
PR 2c — SquashFS and EXT2/3/4
PR 3 — Firmware Agent, rules, evidence and planner integration
PR 4 — Binary triage and bounded disassembly
PR 5 — Candidate validation handoff, Viewer and E2E demo
PR 6 — Selected Ghidra support
PR 7+ — One IoT format adapter per PR
PR 8 — Firmware comparison
```

Each PR must include:

- architecture impact;
- changed files;
- security impact;
- configuration;
- migrations;
- tests;
- backward compatibility;
- known limitations;
- verification commands and results.

---

## 29. Codex execution instructions

Use the following working method:

1. inspect the current repository;
2. run baseline tests;
3. read the current Runner, Agent factory, AgentCoordinator, graph tools, session/resume, Skill loader, runtime backend and report pipeline;
4. determine whether Product Security role infrastructure already exists;
5. write a concrete file-by-file plan for the current phase;
6. implement only one phase or PR scope at a time;
7. write tests before or alongside implementation;
8. run targeted tests continuously;
9. run the full quality gate before claiming completion;
10. self-review for authorization bypass, unsafe paths, unbounded output and backward compatibility.

When an existing Strix extension point can satisfy the requirement, use it rather than introducing a parallel abstraction.

When this specification conflicts with the actual repository, preserve Strix native behavior and document the adaptation.

Do not begin Ghidra, firmware diff or additional filesystem adapters until P1–P5 are stable.

---

## 30. Final acceptance criteria

The first production milestone is complete when:

1. Product Security is opt-in.
2. Native Strix scheduling remains intact.
3. Root can spawn `firmware_analyst` through native child spawning.
4. Agent inputs use immutable artifact IDs, not host paths.
5. Firmware parsing occurs only in restricted one-shot workers.
6. Host verification treats worker output as untrusted.
7. SQLite metadata and content-addressed blobs resume safely.
8. Common firmware formats are safely analyzed.
9. Firmware Agent accesses content only through typed tools.
10. Unauthorized roles cannot access firmware artifacts.
11. Secrets are represented by metadata and handles, not plaintext.
12. Evidence grades and coverage claims constrain conclusions.
13. Planner hints and validation recipes are evidence-backed.
14. Candidate findings contain explicit missing validation.
15. Firmware Agent cannot validate vulnerabilities.
16. Binary ranking is deterministic and explainable.
17. Bounded disassembly works without executing content.
18. Validator can confirm or reject a candidate.
19. Viewer displays status, coverage, hints, recipes and candidate lifecycle.
20. Resume does not duplicate analysis outputs.
21. Normal Strix scans remain backward compatible.
22. All original and new tests pass.

---

## 31. Final product positioning

The recommended first version should be described as:

> A secure, evidence-driven firmware analysis Agent for Strix that safely unpacks untrusted firmware, builds a verified artifact and relation inventory, identifies product-security test opportunities, performs bounded binary inspection, and converts static observations into traceable validation tasks.

It should not yet be described as:

- a fully autonomous firmware exploitation platform;
- a universal firmware emulator;
- a complete reverse-engineering replacement;
- a fleet-wide firmware intelligence graph.

The strategic evolution path is:

```text
Safe extraction
→ verified inventory
→ rule-based security triage
→ bounded binary analysis
→ validation handoff
→ IoT format expansion
→ firmware comparison
→ deeper semantic analysis
```

This sequence delivers useful capability early, preserves Strix's strengths, and avoids making the first implementation too large to review, test or trust.
