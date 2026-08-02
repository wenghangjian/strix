# Firmware P1 Verification Record

## Decision

P1 firmware foundation is accepted for continued development on P2a. The delivered surface supports immutable input ingestion, recoverable metadata/CAS state, trusted role authorization, typed bounded queries, and deterministic queueing. It does not yet run a firmware parser.

The acceptance is conditional only with respect to pre-existing repository-wide type-check baselines described below. The P1 firmware package itself passes pytest, Ruff, mypy, pyright, and Bandit.

## Evidence Identity

- Verification date: 2026-08-02
- Code commit: `850af0950e1b5d7ab7810898ff2707249f4faa70`
- Branch: `codex/secondary-development`
- Checkout: `/srv/penoops/repository`
- Operating system: Ubuntu 22.04.5 LTS
- Architecture: x86_64 / amd64
- Docker: 29.7.1, build `e9452d6`
- Docker Compose: v5.3.1
- Python: CPython 3.12.13 managed by uv

The checkout was clean before the final command sequence. Generated wheels, databases, staging files, and CAS blobs are not committed.

## Passing Gates

| Gate | Result |
| --- | --- |
| `uv run pytest -q` | `666 passed`, 2 existing warnings, 276.66 s |
| `uv run ruff check strix tests` | Passed |
| `uv run pytest -q tests/domains/product_security` | `79 passed` |
| `uv run pytest -q tests/domains/product_security/firmware` | `35 passed` |
| `uv run mypy strix/domains/product_security/firmware` | Passed, 11 source files |
| `uv run pyright strix/domains/product_security/firmware` | 0 errors, 0 warnings |
| `uv run bandit -c pyproject.toml -r strix/domains/product_security/firmware` | No issues identified |
| `uv build` | Built `strix_agent-1.3.1` sdist and wheel |
| Isolated wheel `strix --help` | Passed |
| Disabled-profile acceptance test | `1 passed`; no `domain/firmware` state |

The two pytest warnings are the existing Pydantic 2.11 instance-level `model_fields` deprecations in `strix/config/loader.py`.

## Repository Baselines

The planned repository-wide type/security commands were run and did not pass cleanly for reasons outside the P1 diff:

- `uv run mypy strix` reports 58 errors, all in `strix/interface/tui/app.py`, caused by the current Textual type contract and obsolete ignores.
- `uv run pyright` reports 1048 existing strict-type errors across core modules such as agent factory, config, proxy, reporting, and todo tooling. The P1 package was subsequently reduced to zero pyright errors.
- Full-repository Bandit reports one remaining low-confidence B105 match in `strix/config/codex.py` for the OAuth query parameter `id_token_add_organizations="true"`. The P1 package reports no findings.

These are tracked as repository quality debt, not waived P1 findings. No broad ignore or weakened checker configuration was added.

## Security Review

- Input paths are opened once with no-follow behavior; copy and hash use the acquired descriptor.
- Agents receive immutable IDs and labels, not source host paths or CAS paths.
- SQLite/CAS writes use a journaled recovery sequence and full SHA-256 verification.
- Resume verifies stored blobs and does not require the original source path.
- Coordinator metadata cannot grant firmware permissions; child start and respawn reissue access from live trusted role profiles.
- Root has summary tools only. Direct invocation of queue or metadata tools still performs server-side permission checks.
- Generic `query_domain_artifact` denies the private firmware namespace.
- Summary responses omit input artifact IDs; P1 responses are bounded metadata envelopes.
- Disabled Product Security scans create neither firmware storage nor firmware tools.

## Known Limitation And Next Node

`start_firmware_analysis` returns a persistent `queued` record with the warning `Firmware worker is not available until Phase P2a.` A queued record is incomplete work and must not be reported as analyzed firmware.

The next implementation node is P2a: a pinned restricted worker image, host-side output verification, and safe TAR/ZIP handling. Intel HEX, Motorola S-record, raw disk/MBR/GPT, SquashFS, and EXT2/3/4 remain in P2b/P2c according to the reconciled design.
