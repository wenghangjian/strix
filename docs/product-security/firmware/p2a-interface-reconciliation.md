# P2a Interface Reconciliation

## Authority

`p2a-architecture-spec-implementation-plan.md` is the approved P2a authority. This record maps its expected interfaces onto the P1 implementation without weakening P1 identity or path-hiding guarantees.

## P1 Mapping

| P2a requirement | P1 interface | Decision |
| --- | --- | --- |
| Immutable input identity | `FirmwareInputArtifact` | Used unchanged; remains frozen and contains no host or CAS path. |
| Immutable input reader | Proposed `FirmwareInputArtifact.open_reader()` | Wrapped by `FirmwareRepository.open_input_reader(input_artifact_id)`. Opening storage from an Agent-visible model would couple trusted paths to untrusted metadata. |
| Analysis metadata | `FirmwareAnalysisRecord` | Compatibly extended with P2a persistent states while retaining P1 states for stored rows and API compatibility. |
| Atomic state transition | No P1 compare-and-set API | Added as `FirmwareRepository.transition_analysis(analysis_id, expected, target)`. |
| Verified worker output contract | No P1 equivalent | Composed in Tasks 3, 7, and 15 after its manifest, container-observation, and staging-blob types exist; no `Any`-typed placeholder is introduced. |
| Verified output commit | P1 input-only commit journal | Deferred to Task 18, where migration, artifact-node metadata, CAS promotion, and reconciliation are implemented together. No partial placeholder commit API is exposed in Task 1. |
| Analysis queue | `FirmwareAnalysisService.queue_analysis()` | Used unchanged until Task 17 connects the launcher; deterministic P1 IDs remain stable. |
| Existing CAS | `FirmwareRepository.blob_path()` and `verify_blob()` | Used internally; paths remain unavailable to Agent tools and protocol messages. |

## State Compatibility

P2a adds `created`, `receiving`, `analyzing`, `verified`, `committing`, `timed_out`, `protocol_error`, `cancelled`, `corrupt`, and `not_applicable`. Existing `queued`, `running`, `partial`, `detected_unsupported`, and `unclassified` remain readable. Task 17 will move newly started P2a work from the queue into the detailed state machine; Task 18 owns persisted reconciliation.

## Frozen Boundary

- Host paths never enter `FirmwareInputArtifact`, FWAP messages, worker environment, or container labels.
- The repository opens the CAS descriptor with no-follow semantics, validates regular-file type, size, and full SHA-256 on that descriptor, then rewinds it for streaming.
- State transitions are atomic compare-and-set operations in SQLite and reject stale callers.
- Worker output types are host-only and do not imply persistence until Task 18 completes the transactional commit path.
