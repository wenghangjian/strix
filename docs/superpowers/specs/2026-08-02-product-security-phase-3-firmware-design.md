# Product Security Phase 3 Firmware Analysis Design

**Status:** Approved for implementation planning

**Source requirements:** Product Security Domain Pack task specification, Phase 3

## Objective

Add resume-safe, offline firmware analysis to the opt-in Product Security profile without executing extracted content or replacing Strix's existing agent and sandbox lifecycle.

The Phase 3 vertical slice imports firmware artifacts, identifies embedded content, extracts supported filesystems with strict limits, inventories files, inspects ELF metadata and strings, records redacted credential/key candidates, and publishes structured planner hints.

## Decision

Binwalk is a detector, not the extraction authority and not the completeness oracle.

The pipeline uses three independent layers:

1. Discovery identifies signatures, offsets, entropy regions, and candidate formats.
2. Format-specific extractors unpack only explicitly supported formats.
3. A post-extraction verifier decides whether extraction is complete, partial, failed, or rejected.

A zero process exit code is necessary but never sufficient for extraction success. Warnings, empty regular-file output, incomplete metadata, limit violations, and unsafe paths override the process exit code.

## Supported MVP Formats

- TAR archives through a trusted Python standard-library extractor.
- ZIP archives through a trusted Python standard-library extractor.
- SquashFS images through `unsquashfs` after metadata preflight, with one
  bounded `7z` attempt allowed only when the primary result is partial or failed.

Binwalk v3.1.0 is pinned for signature discovery only. The pipeline does not invoke recursive `binwalk -eM` extraction. Unsupported detected formats remain visible in the analysis with `detected_unsupported` status instead of being reported as successfully extracted.

The sandbox image also provides `file`, `strings`, `readelf`, `objdump`,
`squashfs-tools`, and `7z`. Tool names and versions are recorded in every
analysis result.

## Component Boundaries

### Firmware Models

`strix/domains/product_security/firmware/models.py` owns:

- `FirmwareArtifact`
- `FirmwareManifest`
- `FirmwareFileEntry`
- `FirmwareElfInfo`
- `FirmwareCandidate`
- `FirmwarePlannerHint`
- `FirmwareAnalysis`
- `FirmwareLimits`

The existing artifact service reads and writes:

- `domain/firmware/manifest.json`
- `domain/firmware/analysis.json`
- `domain/firmware/input/<firmware_id>/<original_name>`
- `domain/firmware/extracted/<firmware_id>/...`

Stable firmware IDs use the first 16 hexadecimal characters of the input SHA-256 with a `firmware-` prefix. Duplicate content produces one manifest entry even when submitted under different paths.

### Firmware Importer

`strix/domains/product_security/firmware/ingestion.py` validates configured artifact paths, computes SHA-256 while streaming, rejects non-files and inputs above the configured limit, and atomically copies accepted bytes under `domain/firmware/input/`.

Import does not inspect or execute content. Import errors use stable structured codes.

### Sandbox Worker

`strix/domains/product_security/firmware/sandbox_worker.py` is a trusted, standard-library-first worker copied into the Strix sandbox image at build time. It receives fixed command-line arguments, never evaluates input-derived commands, and emits one JSON result.

The worker performs:

- SHA-256 verification against the imported manifest.
- Whole-file entropy calculation.
- `file` and Binwalk signature discovery.
- Safe format dispatch.
- Post-extraction validation.
- File inventory and hashing.
- ELF detection plus bounded `readelf` metadata.
- Bounded printable-string scanning.
- Certificate, private-key, credential, startup-script, web-root, service, and configuration candidates.
- Planner hint generation.

No extracted executable or script is invoked. `readelf`, `strings`, and `file` only read bytes.

### Host Pipeline

`strix/domains/product_security/firmware/pipeline.py` is the host-side orchestrator. It obtains the existing run-scoped `sandbox_session` from the SDK tool context, streams the imported firmware into `/workspace/.strix/firmware/<firmware_id>/input`, invokes the baked worker with `shell=False`, reads the worker result and validated extracted files, and persists them through `ArtifactRepository`.

Only files listed by a successful worker validation are copied back to the run directory. The host independently rechecks relative paths, file counts, and byte totals before persistence.

Completed analyses are idempotent by input SHA-256, analysis schema version, limits, and toolchain fingerprint. Resume returns the existing valid result instead of re-extracting.

### SDK Tools And Role Isolation

Phase 3 adds run-scoped tools:

- `get_firmware_manifest`
- `analyze_firmware`
- `get_firmware_analysis`

Only `firmware_analyst` receives these tools. The root and test-planner roles may read `firmware/analysis.json` through the existing safe artifact query tool, but cannot run firmware extraction.

The firmware skill instructs the agent to treat `partial`, `failed`, and `rejected` results as incomplete work, not as an empty but successful filesystem.

## Extraction Completeness Contract

`FirmwareAnalysis.extraction_status` is one of:

- `not_attempted`: no supported extraction candidate was found.
- `complete`: all safety and completeness postconditions passed.
- `partial`: regular files exist, but warnings or completeness checks failed.
- `failed`: the extractor failed, timed out, or produced no regular files.
- `rejected`: preflight or runtime safety limits were violated.

`complete` requires all of the following:

- At least one regular file exists.
- The output is not directory-only.
- Every output path is relative and remains below the extraction root.
- No symlink, hard link, device, FIFO, or socket is accepted in the MVP.
- File count, single-file size, and total extracted bytes remain within limits.
- For SquashFS, actual output does not contradict available superblock file-count and size metadata.
- No extractor warning classified as integrity-affecting remains unresolved.

Warnings are persisted as structured `warning_codes` and bounded messages. Warning text never controls the result by itself; deterministic postconditions do.

If `unsquashfs` returns `partial` or `failed`, the MVP may run one bounded
`7z` extraction attempt against the same carved SquashFS image. TAR and ZIP
have no fallback extractor. The pipeline never recursively tries arbitrary
external tools. The final result preserves every attempt and explains which
attempt, if any, was accepted.

## Default Safety Limits

- Maximum imported firmware size: 512 MiB.
- Maximum extracted regular files: 20,000.
- Maximum total extracted bytes: 1 GiB.
- Maximum single extracted file: 128 MiB.
- Maximum nested archive depth: 3.
- Maximum printable strings retained per file: 200.
- Maximum candidate message length: 512 characters.
- Extractor timeout: 180 seconds.
- Per-inspection-command timeout: 30 seconds.

Limits are represented by `FirmwareLimits`, stored in the analysis, and passed as explicit worker arguments. Limit failures are not retryable without a deliberate configuration change.

## Credential And Key Handling

The pipeline records candidate type, file path, line number when available, confidence, and a rule identifier. It never records a complete password, token, private key, or certificate body.

Candidate previews replace the matched value with `<redacted>` and are capped at 160 characters. Tests use obvious synthetic values that are not valid production credentials.

## Planner Feedback

`FirmwareAnalysis.planner_hints` contains auditable, non-executable recommendations with source references such as:

- Telnet configuration -> authentication and default-credential test path.
- Web root or HTTP daemon configuration -> embedded web attack-surface path.
- Upgrade verification strings -> firmware-signature validation path.
- Private-key candidate -> secret-protection and device-identity path.
- ELF network-service binary -> service-specific binary and runtime test path.

The pipeline does not mutate `test_plan.json`. The Test Planning Agent consumes the persisted hints and decides whether to add or revise paths.

## Structured Errors

At minimum, the pipeline distinguishes:

- `FIRMWARE_INPUT_NOT_FOUND`
- `FIRMWARE_INPUT_TOO_LARGE`
- `FIRMWARE_HASH_MISMATCH`
- `FIRMWARE_TOOL_MISSING`
- `FIRMWARE_FORMAT_UNSUPPORTED`
- `FIRMWARE_EXTRACTION_TIMEOUT`
- `FIRMWARE_EXTRACTION_EMPTY`
- `FIRMWARE_EXTRACTION_PARTIAL`
- `FIRMWARE_EXTRACTION_LIMIT_EXCEEDED`
- `FIRMWARE_PATH_TRAVERSAL_BLOCKED`
- `FIRMWARE_SPECIAL_FILE_BLOCKED`
- `FIRMWARE_ANALYSIS_FAILED`

Tool responses retain the existing `{success, error_code, error, ...}` convention. Raw subprocess output is bounded and stored only when it does not contain sensitive material.

## Test Design

All verification runs on the Ubuntu deployment host.

### Unit And Security Tests

- Duplicate firmware input deduplicates by SHA-256.
- ZIP and TAR fixtures extract regular files and produce manifests.
- Absolute paths and `..` traversal entries are rejected before writes.
- Symlink, hard-link, and special-file entries are rejected.
- Directory-only output is `failed`, never `complete`.
- Excess file count, single-file size, total size, nesting, and timeout are rejected.
- Warnings with valid but incomplete output produce `partial`.
- Credential and private-key previews are redacted.
- Extracted content is never executed.

### Docker Integration Fixture

The Ubuntu test creates a deterministic SquashFS fixture at runtime. It contains:

- A copied harmless ELF fixture used only as bytes.
- `/etc/device.conf` with a synthetic test credential.
- A startup script stored as non-executed content.
- A minimal web-root file.
- A service configuration referencing Telnet.

The test verifies filesystem identification, extraction, regular-file inventory, ELF architecture, redacted credential discovery, service inference, planner hints, and persisted manifest/analysis artifacts.

No real firmware image, real credential, or generated extraction directory is committed.

### Compatibility And Regression

- Product Security profile disabled: no firmware tools are registered.
- Non-firmware scans retain existing tool sets and behavior.
- Firmware tool registration remains role-scoped.
- Resume reuses a valid persisted analysis.
- Phase 1-2 targeted tests remain green.
- The complete repository test suite, touched-path Ruff, and touched-path mypy run on Ubuntu.
- The Strix sandbox image is rebuilt and its default entrypoint smoke test is repeated on Ubuntu.

## Non-Goals

- Generic recursive Binwalk extraction.
- Automatic execution or emulation of firmware binaries.
- Ghidra headless analysis.
- UBIFS, JFFS2, YAFFS, CramFS, vendor-encrypted containers, and arbitrary bare-metal symbol recovery.
- Automated exploitation or firmware patching.
- Protocol actions, policy approvals, or validation lifecycle changes from Phases 4-5.

Unsupported formats are reported honestly and remain available for a later adapter without weakening the MVP safety contract.

## External References

- Binwalk v3 repository: https://github.com/ReFirmLabs/binwalk
- Binwalk v3.1.0 release: https://github.com/ReFirmLabs/binwalk/releases/tag/v3.1.0
