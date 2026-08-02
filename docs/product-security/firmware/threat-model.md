# Firmware Analysis Threat Model

## Scope

This model covers firmware ingestion, metadata/blob persistence, Agent tools, one-shot workers, host verification, resume, and downstream evidence handoff. Device-side dynamic validation is outside P1-P3.

## Assets

- Host filesystem, Docker socket, network, credentials, and other scan data.
- Immutable firmware inputs and extracted blobs.
- Firmware metadata, evidence, planner hints, and candidate findings.
- Secret fingerprints and any policy-approved secret material.
- Authorization context, analysis ownership, audit records, and resume state.

## Trust Boundaries

1. User-controlled path to trusted ingestion service.
2. LLM/Agent tool request to trusted Product Security service.
3. Host service to untrusted firmware worker.
4. Untrusted worker output to host verifier.
5. SQLite metadata to content-addressed blob filesystem.
6. Firmware candidate to Validator and formal reporting.

## Threats And Controls

| Threat | Primary controls | Verification |
|---|---|---|
| Path substitution or symlink race during ingestion | no-follow open, descriptor-only streaming, pre/post `fstat`, regular-file check | replace/rename/symlink race tests |
| Oversized or sparse input exhausts host | configured byte limit, counted streaming copy, same-filesystem staging | limit and sparse-file tests |
| Agent supplies a host path or cross-scan ID | ID-only typed tools, scan ownership checks, trusted access context | authorization matrix tests |
| Restored metadata forges permissions | Runner reissues permissions from live role registry; snapshot metadata is descriptive only | forged resume snapshot test |
| Root or wrong role runs worker | separate Root/role tool sets plus server-side permission checks | tool visibility and direct invocation tests |
| Parser compromise escapes worker | one-shot container, no network/mount/device, capability drop, non-root, read-only root, no-new-privileges, seccomp, cgroups | Docker inspect and denied-operation tests |
| Firmware path becomes a host path or command | generated blob names, original bytes encoded as metadata, fixed dispatch table | hostile name and dispatch tests |
| Malicious worker forges manifest or blobs | schema/range/count checks, no-follow copy, host SHA-256 recomputation, all-or-nothing staging | malformed manifest/hash/link tests |
| Archive bomb or sparse logical-size bypass | logical reservations plus actual-byte counters and global limits | compression and sparse fixtures |
| SQLite/blob crash leaves false complete state | explicit commit states, atomic rename, startup reconciliation, hash validation | crash injection at every state |
| Resume reuses stale analysis | canonical key includes input, schema, config, adapters, image, policy, tools, rules, and redaction versions | key-mutation tests |
| Secret reaches model context or logs | metadata/fingerprint handles, bounded redaction, no reveal in Release 1 | log/tool-output scans |
| Weak static signal becomes vulnerability | evidence grades, coverage claims, candidate-only lifecycle, Validator-only promotion | lifecycle and negative-control tests |
| Generic artifact query bypasses firmware policy | deny firmware input/blob namespaces; expose typed redacted queries | traversal and namespace tests |

## Security Invariants

- Imported or extracted bytes are never mounted, executed, sourced, or used as tool arguments that select executable paths.
- Worker success is insufficient; host verification is required before persistence.
- Directory-only extraction is never complete.
- Tool visibility never replaces authorization.
- Static analysis never directly produces a validated vulnerability.
- Non-Product-Security scans do not create firmware state or tools.

## Residual Risks

- Native parser vulnerabilities may corrupt analysis inside the worker before containment stops broader impact.
- Static rules can miss obfuscated, encrypted, inactive, or architecture-specific behavior.
- File inventory does not prove runtime reachability.
- Secret fingerprints still reveal equality across artifacts within the authorized scan.
- Local Docker daemon compromise and host administrator access are outside the worker boundary.

These risks are represented through worker diagnostics, evidence grades, coverage claims, and explicit limitations rather than hidden behind a successful status.
