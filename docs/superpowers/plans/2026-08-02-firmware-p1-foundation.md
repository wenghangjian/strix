# Firmware P1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build immutable firmware ingestion, trusted role authorization, a recoverable SQLite/content-addressed repository, and typed P1 tools without running a firmware parser.

**Architecture:** The existing Product Security JSON repository remains unchanged for small cross-domain artifacts. A dedicated `FirmwareRepository` owns binary inputs and firmware metadata under `domain/firmware`; the Runner ingests configured artifacts before Agent execution and issues trusted access contexts from live role profiles. Root keeps existing Product Security tools plus redacted firmware summaries, while role children receive filtered firmware tools.

**Tech Stack:** Python 3.12+, Pydantic v2, standard-library `sqlite3`, SHA-256 CAS, OpenAI Agents SDK function tools, pytest, Ruff, mypy, pyright, Bandit.

**Execution Status (2026-08-02):** Tasks 1-6 are implemented and P1 acceptance is complete at code commit `850af09`. Task 7 passed full pytest/Ruff plus all P1-scoped gates. Repository-wide mypy, pyright, and Bandit retain pre-existing baseline findings documented in `docs/product-security/firmware/p1-verification.md`; no broad ignores were introduced.

## Global Constraints

- Product Security remains opt-in; disabled and ordinary scans must not create firmware state or tools.
- Agents receive immutable artifact IDs, never source host paths.
- P1 does not start Docker workers, parse firmware, or expose extracted content.
- Coordinator metadata is descriptive and never grants access.
- SQLite and blob promotion use the recovery protocol in `docs/product-security/firmware/design.md`.
- All test and quality-gate execution runs on Ubuntu 22.04 amd64.
- Preserve the existing Runner, AgentCoordinator, child spawning, SDK sessions, and existing Product Security artifact APIs.

---

### Task 1: Firmware Models And Structured Errors

**Files:**
- Create: `strix/domains/product_security/firmware/__init__.py`
- Create: `strix/domains/product_security/firmware/models.py`
- Create: `strix/domains/product_security/firmware/errors.py`
- Create: `tests/domains/product_security/firmware/__init__.py`
- Test: `tests/domains/product_security/firmware/test_models.py`

**Interfaces:**
- Produces: `FirmwareGeometryContract`, `FirmwareInputArtifact`, `FirmwareAnalysisRecord`, `FirmwarePermission`, `FirmwareAccessContext`, `FirmwareToolResult`, and `FirmwareDomainError`.
- ID formats: `fw_input_<sha256-prefix>`, `fw_analysis_<sha256-prefix>`; full hashes remain authoritative and collisions are rejected.

- [ ] **Step 1: Write model and error tests**

```python
def test_access_context_is_runner_issued_and_immutable() -> None:
    access = FirmwareAccessContext(
        scan_id="scan-1",
        agent_id="agent-1",
        role_id="firmware_analyst",
        allowed_input_artifact_ids=frozenset({"fw_input_abc"}),
        permissions=frozenset({FirmwarePermission.METADATA_READ}),
        access_profile="firmware-analyst-v1",
        issued_by="scan_runner",
    )
    with pytest.raises(ValidationError):
        access.agent_id = "agent-2"


def test_geometry_requires_declared_source() -> None:
    with pytest.raises(ValidationError):
        FirmwareGeometryContract(page_size=2048)
```

- [ ] **Step 2: Run the tests and verify collection fails**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_models.py -q`

Expected: FAIL because the firmware package does not exist.

- [ ] **Step 3: Implement strict Pydantic models**

Use frozen models for access and input identity, bounded positive integers for geometry, lowercase 64-character SHA-256 validation, UTC timestamps, and these analysis states:

```python
FirmwareAnalysisStatus = Literal[
    "queued",
    "running",
    "complete",
    "partial",
    "failed",
    "rejected",
    "detected_unsupported",
    "unclassified",
]
```

`FirmwareDomainError` exposes `error_code`, `message`, and `retryable`; its public serializer returns the common `{success, error_code, message, retryable, data, artifact_refs, warnings}` envelope.

- [ ] **Step 4: Run targeted tests**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_models.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the model boundary**

```bash
git add strix/domains/product_security/firmware tests/domains/product_security/firmware/test_models.py
git commit -m "feat(product-security): add firmware domain models"
```

### Task 2: Recoverable Firmware Repository

**Files:**
- Create: `strix/domains/product_security/firmware/repository.py`
- Create: `strix/domains/product_security/firmware/migrations/0001_initial.sql`
- Test: `tests/domains/product_security/firmware/test_repository.py`

**Interfaces:**
- Consumes: Task 1 models and `FirmwareDomainError`.
- Produces: `FirmwareRepository.initialize()`, `register_input()`, `get_input()`, `list_inputs()`, `create_analysis()`, `get_analysis()`, `list_analyses()`, `recover()`, and `verify_blob()`.
- Storage root: `<run>/domain/firmware`; database: `firmware.db`; blobs: `blobs/sha256/<first-two>/<sha256>`.

- [ ] **Step 1: Write migration, CAS, and crash-recovery tests**

```python
def test_repository_promotes_blob_and_metadata(tmp_path: Path) -> None:
    repo = FirmwareRepository(tmp_path / "run")
    repo.initialize()
    artifact = repo.register_input(_staged_input(tmp_path, b"firmware"), _input_meta())
    assert repo.get_input(artifact.input_artifact_id) == artifact
    assert repo.verify_blob(artifact.sha256)


@pytest.mark.parametrize("state", ["staging", "blobs_committed", "metadata_committed"])
def test_recovery_never_exposes_incomplete_commit(tmp_path: Path, state: str) -> None:
    repo = _repository_with_interrupted_commit(tmp_path, state)
    repo.recover()
    assert all(item.commit_state == "complete" for item in repo.list_inputs())
```

Also cover migration idempotency, foreign keys, duplicate full hashes, wrong blob hashes, same-filesystem staging, and concurrent read connections.

- [ ] **Step 2: Verify tests fail before implementation**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_repository.py -q`

Expected: FAIL because `FirmwareRepository` is missing.

- [ ] **Step 3: Add the numbered initial migration**

The migration creates `schema_migration`, `firmware_input`, `firmware_analysis`, `blob`, and `commit_journal`. It enables foreign keys on every connection, requests WAL mode, sets `busy_timeout=5000`, and records the applied migration in the same transaction as schema creation.

- [ ] **Step 4: Implement transaction and recovery primitives**

Use one short-lived SQLite connection per repository operation. Blob registration follows:

```text
write and fsync generated staging file
insert commit_journal(state=staging)
verify hash and atomically rename into CAS
set state=blobs_committed
insert metadata and set state=metadata_committed in one DB transaction
set complete and remove staging record
```

`recover()` validates hashes for promoted blobs, removes abandoned staging, completes valid metadata commits, and deletes metadata that references a missing or mismatched blob. It runs during repository initialization.

- [ ] **Step 5: Run repository tests**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_repository.py -q`

Expected: PASS, including every injected crash state.

- [ ] **Step 6: Commit repository and migration**

```bash
git add strix/domains/product_security/firmware/repository.py strix/domains/product_security/firmware/migrations tests/domains/product_security/firmware/test_repository.py
git commit -m "feat(product-security): add firmware metadata repository"
```

### Task 3: Immutable Descriptor-Based Ingestion

**Files:**
- Create: `strix/domains/product_security/firmware/ingestion.py`
- Create: `strix/domains/product_security/firmware/service.py`
- Test: `tests/domains/product_security/firmware/test_ingestion.py`
- Test: `tests/domains/product_security/firmware/test_service.py`

**Interfaces:**
- Consumes: `FirmwareRepository` and `ProductSecurityConfig.artifacts`.
- Produces: `ingest_firmware_inputs(paths, repository, *, scan_id, project_id, max_input_bytes)` and `FirmwareAnalysisService`.
- P1 service methods: `list_inputs`, `get_input`, `queue_analysis`, `list_analyses`, and `get_summary`.

- [ ] **Step 1: Write hostile ingestion tests**

Cover missing paths, directories, symlinks, path replacement after open, file growth during copy, exact size boundary, oversized input, duplicate bytes under different names, and cleanup after interrupted copy.

```python
def test_ingestion_deduplicates_content_without_exposing_source_path(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    manifest = ingest_firmware_inputs([str(first), str(second)], repo, scan_id="scan-1")
    assert len(manifest) == 1
    assert not hasattr(manifest[0], "source_path")
```

- [ ] **Step 2: Run the ingestion/service tests and verify failure**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_ingestion.py tests/domains/product_security/firmware/test_service.py -q`

Expected: FAIL because ingestion and service modules are missing.

- [ ] **Step 3: Implement descriptor-only streaming ingestion**

Use `os.open` with `O_NOFOLLOW` where available, reject symlinks with `lstat`, verify `fstat` reports a regular file, stream into repository staging while hashing and counting, then compare device/inode/size/mtime metadata before commit. Never reopen the user path after the descriptor is acquired.

- [ ] **Step 4: Implement queue-only P1 service**

`queue_analysis(input_artifact_id)` verifies ownership and creates or returns a deterministic `queued` record. It does not start Docker. The P2 worker bridge will transition this record to `running`.

- [ ] **Step 5: Run targeted tests**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_ingestion.py tests/domains/product_security/firmware/test_service.py -q`

Expected: PASS.

- [ ] **Step 6: Commit ingestion and service**

```bash
git add strix/domains/product_security/firmware/ingestion.py strix/domains/product_security/firmware/service.py tests/domains/product_security/firmware
git commit -m "feat(product-security): ingest immutable firmware inputs"
```

### Task 4: Trusted Firmware Access Context

**Files:**
- Create: `strix/domains/product_security/firmware/access.py`
- Modify: `strix/core/execution.py`
- Modify: `strix/core/runner.py`
- Test: `tests/domains/product_security/firmware/test_access.py`
- Test: `tests/domains/product_security/test_role_spawn.py`

**Interfaces:**
- Produces: `FirmwareAccessIssuer.issue(agent_id, role_profile)` and `require_firmware_permission(ctx, permission, input_artifact_id=None)`.
- Trusted context key: `firmware_access`; no tool accepts access fields as arguments.

- [ ] **Step 1: Write authorization and forged-resume tests**

```python
def test_forged_coordinator_metadata_does_not_grant_worker_execute() -> None:
    issuer = FirmwareAccessIssuer(scan_id="scan-1", input_ids={"fw_input_1"})
    forged = {"role_id": "firmware_analyst", "permissions": ["firmware.worker.execute"]}
    access = issuer.issue(agent_id="child", role_profile=readonly_profile())
    assert FirmwarePermission.WORKER_EXECUTE not in access.permissions
```

Also prove cross-scan IDs, unknown inputs, Root execution, and wrong roles are denied; child spawn and respawn receive newly issued contexts from live `RoleProfile` data.

- [ ] **Step 2: Run authorization tests and verify failure**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_access.py tests/domains/product_security/test_role_spawn.py -q`

Expected: FAIL because trusted access issuance is not wired.

- [ ] **Step 3: Implement permission mapping and checks**

Map role IDs to explicit permissions in trusted Python code. `firmware_analyst` receives summary, metadata, queue, and future worker permissions; Root receives summary only; other P1 roles receive only the redacted queries listed by design.

- [ ] **Step 4: Inject access during child start and respawn**

Runner adds an issuer callable to trusted run context. `spawn_child_agent` and `respawn_subagents` resolve the live role profile and pass a newly issued context into `_start_child_runner`; `_start_child_runner` writes it to `child_ctx`. Coordinator JSON fields are never deserialized into `FirmwareAccessContext`.

- [ ] **Step 5: Run authorization and existing role tests**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_access.py tests/domains/product_security/test_role_spawn.py tests/domains/product_security/test_role_registry.py -q`

Expected: PASS.

- [ ] **Step 6: Commit trusted context integration**

```bash
git add strix/domains/product_security/firmware/access.py strix/core/execution.py strix/core/runner.py tests/domains/product_security
git commit -m "feat(product-security): enforce firmware access context"
```

### Task 5: Root/Role Tool Split And Typed P1 Tools

**Files:**
- Create: `strix/domains/product_security/firmware/tools/__init__.py`
- Create: `strix/domains/product_security/firmware/tools/query.py`
- Create: `strix/domains/product_security/firmware/tools/execution.py`
- Modify: `strix/domains/product_security/tools.py`
- Modify: `strix/domains/product_security/bootstrap.py`
- Modify: `strix/domains/product_security/roles/registry.py`
- Modify: `strix/core/runner.py`
- Test: `tests/domains/product_security/firmware/test_tools.py`
- Test: `tests/domains/product_security/test_product_security_profile.py`
- Test: `tests/domains/product_security/test_domain_tools.py`

**Interfaces:**
- Root tools: `list_firmware_jobs`, `get_firmware_summary`.
- Firmware analyst P1 tools: `list_firmware_inputs`, `get_firmware_job`, `get_firmware_summary`, `start_firmware_analysis`.
- `ProductSecurityRuntime` exposes `root_tools` and `role_tools` separately.

- [ ] **Step 1: Write tool visibility and direct-authorization tests**

Assert Root cannot see or directly invoke `start_firmware_analysis`, firmware analyst can queue an allowed input, another role is denied even when directly invoking the function tool, and errors use the structured firmware envelope.

- [ ] **Step 2: Add sensitive namespace denial tests**

Extend `query_domain_artifact` tests so `firmware/inputs`, `firmware/blobs`, `firmware/staging`, and `firmware.db` return `FIRMWARE_ACCESS_DENIED`; bounded exports remain readable through typed firmware tools only.

- [ ] **Step 3: Run tests and verify failure**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_tools.py tests/domains/product_security/test_product_security_profile.py tests/domains/product_security/test_domain_tools.py -q`

Expected: FAIL because firmware tools and split tool sets do not exist.

- [ ] **Step 4: Implement typed tools and split construction**

Tool handlers retrieve the run-scoped `FirmwareAnalysisService`, call `require_firmware_permission`, return bounded Pydantic envelopes, and never accept paths. Runner passes `root_tools` to `build_strix_agent` and `role_tools` to `make_child_factory`; existing Product Security tools remain available as before.

- [ ] **Step 5: Run tool and profile tests**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_tools.py tests/domains/product_security/test_product_security_profile.py tests/domains/product_security/test_domain_tools.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the P1 tool surface**

```bash
git add strix/domains/product_security strix/agents/factory.py strix/core/runner.py tests/domains/product_security
git commit -m "feat(product-security): add authorized firmware tools"
```

### Task 6: Bootstrap, Resume, And P1 Acceptance

**Files:**
- Modify: `strix/domains/product_security/config.py`
- Modify: `strix/domains/product_security/bootstrap.py`
- Modify: `strix/core/runner.py`
- Modify: `strix/domains/product_security/skills/product_security/firmware_analysis.md`
- Test: `tests/domains/product_security/firmware/test_p1_acceptance.py`
- Test: `tests/domains/product_security/test_product_security_profile.py`

**Interfaces:**
- `ProductSecurityConfig` adds bounded firmware ingestion settings while preserving existing `artifacts` input.
- Bootstrap initializes/reconciles the repository and ingests artifacts before Root starts.
- Resume reuses verified inputs and queued analyses without duplicate rows or blobs.

- [ ] **Step 1: Write P1 end-to-end acceptance tests**

The test builds an enabled runtime with a synthetic binary artifact, verifies immutable ingestion and dedupe, issues Root and firmware analyst contexts, queues one analysis through the typed tool, resumes the runtime, and proves row/blob counts are unchanged. A disabled runtime creates no `domain/firmware` directory.

- [ ] **Step 2: Run acceptance tests and verify failure**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware/test_p1_acceptance.py -q`

Expected: FAIL until bootstrap integration is complete.

- [ ] **Step 3: Implement bootstrap and resume wiring**

Pass trusted `scan_id` into `enable_product_security_domain` and initialize `FirmwareRepository` for every enabled Product Security run, even when no artifacts are configured, so summary tools return an empty result instead of missing context. Derive `project_id` from persisted Product Context when available. Store the service and issuer under trusted context keys, ingest before agent construction, and make repeated bootstrap/resume idempotent.

- [ ] **Step 4: Update the firmware skill**

The skill instructs the analyst to select IDs, queue or resume analysis, report that P1 has no parser worker, never request host paths, and treat queued work as incomplete.

- [ ] **Step 5: Run P1 targeted suite**

Run on Ubuntu: `uv run pytest tests/domains/product_security/firmware tests/domains/product_security -q`

Expected: PASS.

- [ ] **Step 6: Commit P1 bootstrap**

```bash
git add strix/domains/product_security strix/core/runner.py tests/domains/product_security
git commit -m "feat(product-security): bootstrap firmware analysis foundation"
```

### Task 7: Ubuntu Quality Gate And Delivery Record

**Files:**
- Modify: `docs/product-security/firmware/architecture.md`
- Create: `docs/product-security/firmware/p1-verification.md`

**Interfaces:**
- Produces an exact commit/image/environment verification record; no generated databases or blobs are committed.

- [ ] **Step 1: Run repository quality gates on Ubuntu**

```bash
uv run pytest -q
uv run ruff check strix tests
uv run mypy strix
uv run pyright
uv run bandit -c pyproject.toml -r strix
uv build
```

Expected: every command exits 0.

- [ ] **Step 2: Run package and disabled-profile smoke tests**

Run the installed CLI help and a deterministic disabled-profile bootstrap test. Confirm no `domain/firmware` state appears for disabled scans.

- [ ] **Step 3: Record verification evidence**

Write the Ubuntu release, architecture, Docker version, Git commit, command list, pass counts, and known P1 limitation: analysis records can be queued but no worker executes until P2a.

- [ ] **Step 4: Review the complete P1 diff**

Check authorization bypasses, path reopening, filesystem/database crash windows, unbounded outputs, migration packaging, Product Security disabled behavior, and unrelated core changes.

- [ ] **Step 5: Commit verification documentation**

```bash
git add docs/product-security/firmware
git commit -m "docs(product-security): record firmware p1 verification"
```
