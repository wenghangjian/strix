# Strix Product Security P2a — Firmware Worker Architecture, Protocol Specification, and Implementation Plan

> **Document role:** P2a authoritative architecture and implementation specification  
> **Target project:** Strix Product Security Domain Pack  
> **Scope:** Restricted one-shot firmware worker, Docker attach framed protocol, host verifier, TAR/ZIP adapters, commit/recovery integration  
> **Version:** 1.0  
> **Date:** 2026-08-02  
> **Status:** Approved architecture, ready for implementation  
> **Prerequisite:** P1a and P1b have established immutable firmware inputs, trusted access context, Root/role tool isolation, SQLite metadata storage, CAS blob storage, migrations, and reconciliation state handling.

---

# Part I — Architecture and Normative Specification

## 1. Purpose

P2a delivers the first executable firmware-analysis worker for the Product Security domain.

It creates a secure transport and execution boundary between the Strix host process and untrusted firmware parsing code. It supports strict TAR and ZIP analysis only. The worker receives one immutable firmware image through Docker attach stdin, performs bounded archive preflight and extraction inside a one-shot restricted container, and returns one manifest plus generated regular-file blobs through Docker attach stdout.

The host independently validates all returned data before committing any metadata or blob reference.

```text
immutable FirmwareInputArtifact
→ restricted one-shot Docker worker
→ strict TAR/ZIP preflight
→ bounded internal staging
→ manifest
→ generated blob stream
→ host verification
→ CAS commit
→ SQLite metadata commit
→ complete FirmwareAnalysis
```

P2a does not implement firmware reasoning, rule packs, binary analysis, candidate findings, SquashFS, EXT, partition parsing, record formats, Ghidra, or dynamic testing.

---

## 2. Architectural decision

### 2.1 Selected transport

P2a uses:

> **Docker attach bidirectional byte streams with a repository-owned framed protocol consisting of a fixed 32-byte binary header and a bounded variable-length payload.**

Host-to-worker traffic uses container stdin.

Worker-to-host traffic uses container stdout.

Docker stderr is not attached. Docker persistent logging is disabled.

### 2.2 Rejected alternatives

#### Docker `put_archive` / `get_archive`

Rejected because it introduces a second untrusted TAR parsing layer, requires temporary-file coordination, complicates streaming limits, and creates a second transfer protocol.

#### Host-side extraction

Rejected because it violates the approved worker-isolation boundary.

#### Bind mounts, named volumes, and `docker cp`

Rejected because they expose host filesystem paths or create transfer paths outside the audited protocol.

### 2.3 Consequence

Docker attach is the only firmware and generated-blob transfer path in P2a. No fallback is permitted.

---

## 3. Scope

### 3.1 Included

- repository-built firmware-worker image;
- one-shot restricted Docker lifecycle;
- Docker attach stdin/stdout transport;
- Docker raw-stream stdout demultiplexing;
- fixed-header application framing;
- protocol and worker state machines;
- immutable firmware input streaming;
- worker-side input hash and size validation;
- strict TAR preflight and regular-file export;
- strict ZIP preflight and regular-file export;
- worker-side generated-blob staging;
- manifest generation;
- host-side manifest validation;
- host-side streamed blob receipt;
- host-side count, size, CRC, SHA-256, schema, path, and status verification;
- all-or-nothing acceptance;
- CAS and SQLite commit integration;
- interrupted-job reconciliation;
- structured failure mapping;
- container security tests;
- protocol fault-injection tests;
- hostile TAR/ZIP fixtures;
- end-to-end resume-safe tests.

### 3.2 Excluded

- SquashFS and EXT;
- MBR/GPT and HEX/S-record;
- uImage/FIT, UBI/UBIFS, JFFS2, YAFFS;
- raw NAND geometry;
- binary inspection and Ghidra;
- firmware rules, planner hints, validation recipes, candidate findings;
- Viewer redesign;
- network or hardware testing;
- firmware execution or emulation.

---

## 4. Trust model

### 4.1 Trusted components

- Strix host process;
- `FirmwareAccessContext` issued by the Scan Runner;
- immutable firmware input repository;
- P1b SQLite repository and CAS;
- P2a Docker launcher;
- Docker raw-stream decoder;
- FWAP frame decoder;
- host manifest validator and verifier;
- repository-owned worker source and Dockerfile;
- repository-owned seccomp profile;
- pinned worker image digest.

### 4.2 Untrusted components and data

- firmware bytes;
- TAR/ZIP metadata, names, sizes, CRCs, compressed data;
- worker manifest;
- worker blob frames;
- worker progress and result;
- container exit code;
- container filesystem;
- generated names until validated;
- all worker output after any protocol inconsistency.

### 4.3 Security rule

No successful worker exit, parser exit code, adapter status, or manifest claim is sufficient. The host independently verifies the full accepted output set.

---

## 5. Component architecture

```text
FirmwareAnalysisService
        ↓
FirmwareWorkerLauncher
        ↓
Docker attach transport
        ↓
Restricted Firmware Worker
        ↓
HostOutputReceiver + HostVerifier
        ↓
FirmwareRepository
        ↓
CAS + SQLite
```

### 5.1 Responsibilities

**FirmwareAnalysisService**

- verifies authorization and scan ownership;
- transitions persistent analysis state;
- invokes launcher;
- maps terminal results.

**FirmwareWorkerLauncher**

- creates the container;
- starts and attaches;
- owns protocol deadlines and cancellation;
- inspects and destroys the container in `finally`.

**Docker attach transport**

- writes raw stdin bytes;
- demultiplexes Docker stdout;
- exposes a bounded byte stream to FWAP.

**Firmware Worker**

- validates request and input identity;
- selects TAR or ZIP adapter;
- performs full preflight;
- exports only generated regular-file blobs;
- sends manifest, blobs, and result.

**HostOutputReceiver and HostVerifier**

- validate protocol;
- reserve manifest output;
- stream to generated staging files;
- recompute hashes;
- produce `VerifiedWorkerOutput` only after complete success.

**FirmwareRepository**

- commits immutable blobs idempotently;
- commits metadata transactionally;
- reconciles interrupted states.

---

## 6. Recommended package layout

```text
strix/domains/product_security/firmware/
  protocol/
    constants.py
    errors.py
    frame.py
    messages.py
    state.py

  runtime/
    docker_attach.py
    worker_container.py
    worker_launcher.py

  worker/
    __main__.py
    session.py
    limits.py
    paths.py
    staging.py
    manifest.py
    export.py
    adapters/
      base.py
      tar.py
      zip.py

  host/
    manifest_validator.py
    staging.py
    output_receiver.py
    verifier.py

  service.py
  repository.py
  models.py
  errors.py
  config.py

docker/firmware-worker/
  Dockerfile
  seccomp.json
  build-image.sh
  verify-image.py
  worker-image.lock
```

Tests mirror this structure under:

```text
tests/domains/product_security/firmware/
```

---

# 7. Docker worker image

## 7.1 Build model

Use a repository-owned multi-stage Dockerfile.

The final image contains only:

- required Python or compiled runtime;
- repository-owned worker code;
- required standard-library decompression support;
- fixed entrypoint.

It contains no:

- shell;
- package manager;
- compiler;
- Docker CLI;
- network tools;
- archive CLI;
- unrelated Strix application modules.

Every `FROM` reference is digest-pinned.

`worker-image.lock` records:

```text
image_tag
image_digest
base_image_reference
base_image_digest
worker_source_digest
protocol_version
manifest_schema_version
built_at_utc
```

## 7.2 Runtime identity

```text
UID 65532
GID 65532
```

Fixed entrypoint:

```text
/app/firmware-worker
```

or a fixed distroless Python entrypoint chosen during image implementation.

## 7.3 Runtime configuration

```text
Tty=false
OpenStdin=true
AttachStdin=true
AttachStdout=true
AttachStderr=false

NetworkMode=none
ReadonlyRootfs=true
CapDrop=ALL
NoNewPrivileges=true
PidsLimit=64
NanoCPUs=2000000000
Memory=4294967296
MemorySwap=4294967296
OomKillDisable=false

LogDriver=none
AutoRemove=false
```

Forbidden:

- binds;
- mounts;
- named volumes;
- volumes-from;
- devices;
- device cgroup rules;
- privileged mode;
- host PID/IPC/network;
- added capabilities.

## 7.4 Writable work area

Only `/work` is writable.

```text
rw,noexec,nosuid,nodev,size=2147483648,mode=0700
```

Fixed worker paths:

```text
/work/input.bin
/work/output/
/work/metadata/
```

Archive names never determine these paths.

## 7.5 Security profiles

Repository-owned seccomp denies at minimum:

- mount and unmount;
- pivot root;
- namespace creation;
- ptrace;
- kernel module operations;
- privileged device operations;
- socket creation and networking;
- reboot and system management.

Use AppArmor `docker-default` at minimum.

## 7.6 Environment

```text
PYTHONHASHSEED=0
PYTHONDONTWRITEBYTECODE=1
PYTHONUNBUFFERED=1
LANG=C.UTF-8
LC_ALL=C.UTF-8
```

No credentials, proxy variables, host paths, or Docker socket details are passed.

---

# 8. Docker attach transport

## 8.1 Layering

```text
Docker hijacked connection
→ Docker raw-stream decoder
→ worker stdout bytes
→ FWAP frame decoder
```

Host writes FWAP bytes directly to stdin.

## 8.2 Docker raw-stream decoder

With `Tty=false`, stdout can use an 8-byte Docker header:

```text
byte 0      stream type
bytes 1-3   zero
bytes 4-7   big-endian payload length
```

Only stream type `1` is accepted.

Type `2` stderr, unknown types, non-zero reserved bytes, truncation, or oversized Docker payload terminate the run.

## 8.3 Attach interface

```python
class DockerAttachSession(Protocol):
    def write_all(self, data: bytes) -> None: ...
    def read_stdout(self, max_bytes: int) -> bytes: ...
    def shutdown_write(self) -> None: ...
    def close(self) -> None: ...
```

Blocking socket operations run outside the main asyncio event loop.

## 8.4 Backpressure

```text
decoded Docker stdout buffer: max 2 MiB
global FWAP frame payload: max 8 MiB
pending blob chunks: max 2
```

Blob chunks are staged before the next large chunk is accepted.

## 8.5 Lifecycle

```text
create
→ start
→ attach
→ HELLO within 10 seconds
→ protocol run
→ inspect
→ close
→ kill if running
→ wait
→ force remove
```

The worker blocks on `HELLO` and emits no bytes before it.

---

# 9. FWAP frame protocol

## 9.1 Identity

```text
Name: FWAP
Version: 1.0
Byte order: big-endian
```

No version negotiation in P2a.

## 9.2 Fixed 32-byte header

```text
Offset  Size  Field
0       4     magic
4       1     major_version
5       1     minor_version
6       1     message_type
7       1     flags
8       4     stream_id
12      4     sequence
16      8     payload_length
24      4     payload_crc32
28      4     header_crc32
```

Magic:

```text
FWAP
```

Header CRC is IEEE CRC-32 over bytes `0..27`.

Payload CRC is IEEE CRC-32 over payload; zero for empty payload.

CRC detects framing corruption. SHA-256 establishes blob identity.

## 9.3 Flags

```text
0x01 JSON_PAYLOAD
0x02 FINAL
```

Other bits must be zero.

## 9.4 Sequence

Each direction has an independent global sequence, starting at zero and increasing by exactly one.

Reject duplicates, skips, out-of-order frames, and wraparound.

## 9.5 Streams

```text
0 = control
1 = input
4096 + ordinal = output blob stream
```

Every blob stream is declared in the manifest.

Only one blob stream may be active at a time.

## 9.6 Payload limits

```text
global frame maximum:          8 MiB
HELLO / HELLO_ACK:            64 KiB
ANALYSIS_REQUEST:            256 KiB
REQUEST_ACCEPTED:             64 KiB
INPUT_BEGIN / INPUT_END:      64 KiB
INPUT_ACCEPTED:               64 KiB
INPUT_CHUNK:                   1 MiB
MANIFEST:                      8 MiB
MANIFEST_ACCEPTED:            64 KiB
BLOB_BEGIN / BLOB_END:        64 KiB
BLOB_CHUNK:                    1 MiB
PROGRESS:                      16 KiB
RESULT:                       256 KiB
ERROR:                         64 KiB
CANCEL:                        64 KiB
```

The decoder checks the message limit before allocating payload storage.

## 9.7 JSON rules

- UTF-8;
- no BOM;
- object top level;
- no NaN or Infinity;
- compact encoding;
- strict Pydantic validation;
- unknown fields rejected.

---

# 10. Message types and flow

```python
class MessageType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    ANALYSIS_REQUEST = 0x03
    REQUEST_ACCEPTED = 0x04
    INPUT_BEGIN = 0x05
    INPUT_CHUNK = 0x06
    INPUT_END = 0x07
    INPUT_ACCEPTED = 0x08
    MANIFEST = 0x09
    MANIFEST_ACCEPTED = 0x0A
    BLOB_BEGIN = 0x0B
    BLOB_CHUNK = 0x0C
    BLOB_END = 0x0D
    PROGRESS = 0x0E
    RESULT = 0x0F
    ERROR = 0x10
    CANCEL = 0x11
```

Normal flow:

```text
HELLO
← HELLO_ACK
ANALYSIS_REQUEST
← REQUEST_ACCEPTED
INPUT_BEGIN
INPUT_CHUNK × N
INPUT_END
← INPUT_ACCEPTED
← PROGRESS × N
← MANIFEST
MANIFEST_ACCEPTED
← BLOB_BEGIN / BLOB_CHUNK × N / BLOB_END × M
← RESULT
EOF
```

Manifest validation failure:

```text
← MANIFEST
CANCEL
kill and remove container
reject complete run
```

---

# 11. Core message schemas

## 11.1 HELLO

```json
{
  "protocol_major": 1,
  "protocol_minor": 0,
  "session_id": "fwap_session_uuid",
  "analysis_id": "fw_analysis_uuid",
  "host_implementation": "strix",
  "maximum_frame_payload": 8388608
}
```

## 11.2 HELLO_ACK

```json
{
  "protocol_major": 1,
  "protocol_minor": 0,
  "session_id": "fwap_session_uuid",
  "worker_build_id": "source_digest",
  "worker_protocol": "1.0",
  "manifest_schema": "p2a-manifest-1",
  "supported_adapters": ["archive/tar-v1", "archive/zip-v1"],
  "limits_profile": "p2a-default-v1"
}
```

## 11.3 ANALYSIS_REQUEST

```json
{
  "request_schema": "p2a-request-1",
  "analysis_id": "fw_analysis_uuid",
  "input_artifact_id": "fw_input_uuid",
  "declared_input_size": 123456,
  "declared_input_sha256": "64_lowercase_hex",
  "enabled_adapters": ["archive/tar-v1", "archive/zip-v1"],
  "limits": {
    "maximum_input_bytes": 536870912,
    "maximum_output_bytes": 1073741824,
    "maximum_file_bytes": 134217728,
    "maximum_regular_files": 20000,
    "maximum_manifest_bytes": 8388608,
    "input_chunk_bytes": 1048576,
    "output_chunk_bytes": 1048576,
    "analysis_timeout_seconds": 180
  }
}
```

## 11.4 INPUT_BEGIN

```json
{
  "analysis_id": "fw_analysis_uuid",
  "input_artifact_id": "fw_input_uuid",
  "declared_size": 123456,
  "declared_sha256": "64_lowercase_hex"
}
```

`INPUT_CHUNK` contains raw bytes.

## 11.5 INPUT_END

```json
{
  "analysis_id": "fw_analysis_uuid",
  "actual_size": 123456,
  "actual_sha256": "64_lowercase_hex"
}
```

## 11.6 MANIFEST_ACCEPTED

```json
{
  "analysis_id": "fw_analysis_uuid",
  "manifest_sha256": "64_lowercase_hex",
  "accepted_blob_count": 10,
  "accepted_total_bytes": 1234567
}
```

## 11.7 BLOB_BEGIN

```json
{
  "analysis_id": "fw_analysis_uuid",
  "blob_id": "blob_00000000",
  "stream_id": 4096,
  "declared_size": 1000,
  "declared_sha256": "64_lowercase_hex"
}
```

`BLOB_CHUNK` contains raw bytes.

## 11.8 BLOB_END

```json
{
  "analysis_id": "fw_analysis_uuid",
  "blob_id": "blob_00000000",
  "actual_size": 1000,
  "actual_sha256": "64_lowercase_hex"
}
```

## 11.9 RESULT

```json
{
  "analysis_id": "fw_analysis_uuid",
  "status": "complete",
  "adapter_id": "archive/zip-v1",
  "manifest_sha256": "64_lowercase_hex",
  "emitted_blob_count": 10,
  "emitted_total_bytes": 1234567,
  "warning_codes": [],
  "worker_duration_ms": 1200
}
```

Allowed statuses:

```text
complete
partial
rejected
detected_unsupported
not_applicable
unclassified
```

`failed` uses `ERROR`.

## 11.10 ERROR

```json
{
  "analysis_id": "fw_analysis_uuid",
  "error_code": "WORKER_INPUT_HASH_MISMATCH",
  "phase": "input",
  "message": "Received input did not match declared identity",
  "retryable": false
}
```

No stack trace, archive name, secret, or file content is included.

---

# 12. Protocol state machines

## 12.1 Host

```text
CREATED
→ CONTAINER_STARTED
→ ATTACHED
→ HELLO_SENT
→ HELLO_CONFIRMED
→ REQUEST_SENT
→ REQUEST_ACCEPTED
→ INPUT_STREAMING
→ INPUT_CONFIRMED
→ WAITING_MANIFEST
→ MANIFEST_VALIDATED
→ RECEIVING_BLOBS
→ RESULT_RECEIVED
→ OUTPUT_VERIFIED
→ COMMITTING
→ COMPLETE
```

Terminal:

```text
CANCELLED
TIMED_OUT
PROTOCOL_ERROR
WORKER_ERROR
CONTAINER_ERROR
OUTPUT_REJECTED
CORRUPT
```

## 12.2 Worker

```text
WAIT_HELLO
→ WAIT_REQUEST
→ WAIT_INPUT_BEGIN
→ RECEIVE_INPUT
→ VERIFY_INPUT
→ ANALYZE
→ WAIT_MANIFEST_ACCEPTANCE
→ EXPORT_BLOBS
→ SEND_RESULT
→ EXIT
```

Any frame not explicitly allowed in the current state is `FWAP_UNEXPECTED_MESSAGE`.

---

# 13. Manifest schema

```python
class P2AManifest(BaseModel):
    manifest_schema: Literal["p2a-manifest-1"]
    protocol_version: Literal["1.0"]
    analysis_id: str
    input_artifact_id: str
    input_size: int
    input_sha256: str
    adapter_id: Literal["archive/tar-v1", "archive/zip-v1"] | None
    adapter_version: str | None
    status: Literal[
        "complete",
        "partial",
        "rejected",
        "detected_unsupported",
        "not_applicable",
        "unclassified",
    ]
    generated_at_utc: datetime
    worker_build_id: str
    blob_count: int
    total_blob_bytes: int
    blobs: list["P2AManifestBlob"]
    warning_codes: list[str]
    rejected_entry_count: int
    ignored_directory_count: int
    limits_profile: Literal["p2a-default-v1"]
```

```python
class P2AManifestBlob(BaseModel):
    blob_id: str
    stream_id: int
    ordinal: int
    generated_storage_name: str
    size_bytes: int
    sha256: str
    relation: Literal["extracted"]
    parent_input_artifact_id: str
    path: "ArchivePathMetadata"
    archive: "ArchiveMemberMetadata"
```

```python
class ArchivePathMetadata(BaseModel):
    display_path: str
    canonical_path: str
    raw_name_b64: str | None
    path_encoding: str | None
```

```python
class ArchiveMemberMetadata(BaseModel):
    member_index: int
    member_type: Literal["regular_file"]
    declared_size: int
    actual_size: int
    compression_method: str
    crc32: int | None
    unix_mode: int | None
    uid: int | None
    gid: int | None
    mtime_utc: datetime | None
```

Zero blobs are allowed only for:

```text
rejected
detected_unsupported
not_applicable
unclassified
```

`complete` requires at least one regular file.

A directory-only archive is rejected.

---

# 14. Archive path policy

For every member:

1. reject NUL;
2. reject empty regular-file name;
3. convert backslash to slash for security evaluation;
4. reject `/`, `//`, UNC, or drive-prefixed paths;
5. remove empty and `.` components;
6. reject any `..`;
7. normalize Unicode to NFC;
8. join with `/`;
9. reject canonical path over 4096 UTF-8 bytes;
10. reject a component over 255 UTF-8 bytes;
11. reject duplicate canonical paths.

Case remains significant.

Archive paths are metadata only and never become storage paths.

Reject the complete archive for:

- symlink or hard link;
- character/block device;
- FIFO or socket;
- sparse TAR;
- unsupported TAR type;
- encrypted ZIP;
- unsupported ZIP compression;
- malformed PAX;
- normalized-path collision;
- duplicate entry;
- invalid CRC;
- dishonest size;
- per-file limit;
- total output limit;
- file-count limit.

---

# 15. TAR adapter

Supported:

```text
plain TAR
TAR.GZ
TAR.XZ
```

TAR.BZ2 is `detected_unsupported`.

Rules:

- never call `extract` or `extractall`;
- iterate full table before export;
- reject all unsupported types;
- reserve declared totals before extraction;
- use `extractfile`;
- write generated worker names only;
- stream count and SHA-256;
- compare actual and declared size;
- clear complete staging on any failure.

`complete` requires all regular files exported and at least one regular file.

---

# 16. ZIP adapter

Supported compression:

```text
ZIP_STORED
ZIP_DEFLATED
```

Rejected:

```text
ZIP_BZIP2
ZIP_LZMA
unknown methods
encrypted entries
```

Preflight validates:

- central directory;
- count;
- names;
- flags;
- method;
- compressed and uncompressed size;
- ZIP64;
- duplicate canonical paths;
- Unix external attributes;
- limits.

Export:

- generated names only;
- streamed decompression;
- byte count;
- SHA-256;
- CRC verification;
- all-or-nothing cleanup.

---

# 17. Worker staging and export

Input:

```text
/work/input.bin
```

Output:

```text
/work/output/blob_00000000
/work/output/blob_00000001
...
```

Generated name regex:

```text
^blob_[0-9]{8}$
```

The worker completes preflight and staging before sending the manifest so every blob already has final size and SHA-256.

After `MANIFEST_ACCEPTED`, it streams blobs sequentially in 1 MiB chunks.

---

# 18. Host Manifest validation

Before acknowledgement, validate:

- raw JSON size;
- schema and protocol version;
- analysis/input identity;
- input hash and size;
- adapter/status;
- blob count and total;
- per-blob size;
- ID and generated-name syntax;
- ordinal continuity;
- stream-ID formula;
- uniqueness;
- path policy;
- metadata bounds;
- zero-blob status rules;
- host reservation.

Compute:

```text
manifest_sha256 = SHA-256(raw manifest payload)
```

---

# 19. Host output staging

Trusted path:

```text
<scan-run>/domain/firmware/staging/<analysis-id>/<run-id>/
```

Permissions:

```text
0700 directories
0600 files
```

Per blob:

```text
BLOB_BEGIN
→ exclusive generated staging file
→ chunked write + SHA-256 + byte count
→ fsync
→ BLOB_END verification
```

Reject the complete run for:

- undeclared blob;
- duplicate blob;
- wrong stream;
- interleaving;
- overrun/underrun;
- wrong hash;
- missing blob;
- result mismatch;
- result missing;
- trailing bytes;
- worker exit mid-frame.

---

# 20. Persistent states and commit

States:

```text
created
receiving
analyzing
verified
committing
complete

rejected
failed
timed_out
protocol_error
cancelled
corrupt
```

Normal transitions:

```text
created → receiving → analyzing → verified → committing → complete
```

Commit:

1. receiver completes verification;
2. persist `verified`;
3. copy blobs idempotently to CAS by SHA-256;
4. begin SQLite transaction;
5. insert/reuse blob rows;
6. insert artifact nodes and archive metadata;
7. insert attempt and summary;
8. set `complete` in same transaction;
9. commit;
10. remove staging.

Reconciliation:

| Condition | Action |
|---|---|
| `receiving`/`analyzing` | mark interrupted and remove staging |
| `verified`/`committing` | rerun idempotent commit |
| `complete` + staging | remove staging |
| CAS without reference | mark orphan candidate |
| metadata reference without CAS | mark `corrupt` |
| terminal state + labeled running container | force-remove container |

Do not delete orphan CAS in the same pass.

---

# 21. Timeouts and cancellation

```text
container creation:          30 s
attach establishment:       10 s
HELLO:                       10 s
request acceptance:         10 s
input idle:                  30 s
input total:                600 s
analysis:                   180 s
manifest acceptance:         15 s
blob idle:                   30 s
total worker run:           900 s
cancel grace:                 1 s
container stop wait:          5 s
```

Use monotonic clocks.

Cancellation:

```text
send CANCEL if possible
→ wait 1 s
→ kill
→ inspect
→ remove
→ clear staging
→ persist cancelled
```

---

# 22. Error taxonomy

Protocol:

```text
FWAP_BAD_DOCKER_STREAM
FWAP_BAD_MAGIC
FWAP_UNSUPPORTED_VERSION
FWAP_BAD_HEADER_CRC
FWAP_BAD_PAYLOAD_CRC
FWAP_BAD_FLAGS
FWAP_PAYLOAD_TOO_LARGE
FWAP_TRUNCATED_HEADER
FWAP_TRUNCATED_PAYLOAD
FWAP_SEQUENCE_MISMATCH
FWAP_UNKNOWN_MESSAGE
FWAP_UNEXPECTED_MESSAGE
FWAP_UNKNOWN_STREAM
FWAP_DUPLICATE_BLOB
FWAP_RESULT_MISSING
FWAP_TRAILING_OUTPUT
```

Worker:

```text
WORKER_REQUEST_INVALID
WORKER_LIMIT_INVALID
WORKER_INPUT_TOO_LARGE
WORKER_INPUT_SIZE_MISMATCH
WORKER_INPUT_HASH_MISMATCH
WORKER_FORMAT_AMBIGUOUS
WORKER_TAR_REJECTED
WORKER_ZIP_REJECTED
WORKER_OUTPUT_LIMIT_EXCEEDED
WORKER_FILE_LIMIT_EXCEEDED
WORKER_MANIFEST_TOO_LARGE
WORKER_MANIFEST_NOT_ACCEPTED
WORKER_INTERNAL_ERROR
```

Host verification:

```text
HOST_MANIFEST_SCHEMA_INVALID
HOST_MANIFEST_IDENTITY_MISMATCH
HOST_MANIFEST_LIMIT_EXCEEDED
HOST_MANIFEST_DUPLICATE_ID
HOST_MANIFEST_PATH_INVALID
HOST_BLOB_UNDECLARED
HOST_BLOB_SIZE_MISMATCH
HOST_BLOB_HASH_MISMATCH
HOST_BLOB_MISSING
HOST_RESULT_MISMATCH
HOST_WORKER_OOM
HOST_WORKER_EXIT_UNEXPECTED
HOST_COMMIT_FAILED
HOST_CAS_CORRUPT
```

---

# 23. Logging and audit

Docker log driver is `none`.

Worker stdout contains FWAP frames only. No `print`.

Host logs may include IDs, digest, phase, message type, counts, status, error code, and duration.

Do not log firmware bytes, blob bytes, rejected archive names, credentials, complete manifest, or normal-user stack traces.

Audit record:

```text
analysis_id
input_artifact_id
container_id
worker_image_digest
worker_build_id
protocol_version
manifest_schema
adapter_id
effective_limits
timestamps
final_state
exit_code
OOMKilled
error_code
manifest_sha256
blob_count
total_output_bytes
```

---

# 24. Concurrency

Default:

```text
maximum concurrent firmware workers = 1
```

Use a process-wide semaphore.

Increase to two only after explicit memory-pressure validation.

---

# 25. Security invariants

1. One analysis uses one new container.
2. One container receives one input.
3. Firmware enters only through FWAP stdin.
4. Blobs leave only through FWAP stdout.
5. No mount, volume, device, or Docker copy API is used.
6. Archive names never become storage paths.
7. Extracted content is never executed.
8. Worker has no network.
9. Worker is non-root.
10. Rootfs is read-only.
11. Work tmpfs is noexec/nosuid/nodev.
12. Host independently validates output.
13. Any protocol inconsistency rejects all output.
14. Any archive safety violation rejects the archive.
15. CAS is immutable.
16. SQLite commit is transactional.
17. Interrupted states reconcile.
18. Cleanup runs on all paths.
19. Output is bounded.
20. Product Security disabled behavior is unchanged.

---

# 26. Test matrix

## Frame codec

- exact 32-byte header;
- big-endian;
- CRC;
- empty/max payload;
- fragmented header/payload;
- multiple frames;
- bad magic/version/flags/CRC;
- overflow;
- sequence errors;
- truncation;
- deterministic random-byte fuzz.

## Docker raw-stream

- valid stdout;
- fragmented Docker header/payload;
- multiple frames;
- stderr;
- reserved-byte error;
- overlimit;
- EOF mid-header/payload.

## State machines

Test every valid transition and all invalid state/message pairs.

## Container

Verify no network, mounts, binds, volumes, devices, added capabilities; all caps dropped; non-root; read-only; no-new-privileges; seccomp; AppArmor; tmpfs flags; CPU/PID/memory/swap; no logs; TTY false; no stderr.

## TAR

Valid TAR/TAR.GZ/TAR.XZ, zero-byte file, nested path, absolute/traversal/backslash/drive/UNC, duplicate canonical path, links, devices, FIFO, sparse, PAX, dishonest size, limits, directory-only, truncation, ambiguous format.

## ZIP

Valid stored/deflated/ZIP64, encryption, unsupported methods, CRC, unsafe paths, duplicate, symlink attributes, limits, directory-only, truncated central directory, dishonest size.

## Host output

Valid manifest/blobs, identity mismatch, duplicate IDs/streams, invalid names/path, undeclared/duplicate/wrong/missing blob, result mismatch/missing, trailing output, exit mid-blob.

## Lifecycle

Success, rejected archive, protocol error, input/analysis timeout, OOM, ENOSPC, cancel, attach failure, commit failure, reconciliation, orphan, missing CAS.

## E2E

1. valid TAR complete;
2. valid ZIP complete;
3. malicious TAR commits nothing;
4. malicious ZIP commits nothing;
5. corrupt protocol creates `protocol_error`;
6. interruption leaves no partial result;
7. reconciliation safely resumes commit;
8. original Strix tests pass.

---

# Part II — Implementation Plan

# P2a Firmware Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a restricted one-shot Docker firmware worker that receives immutable firmware through FWAP, safely analyzes TAR/ZIP, returns a verified manifest and generated blobs, and commits accepted output through P1b CAS and SQLite.

**Architecture:** One Docker container per analysis; Docker attach is the only byte transfer path. The worker preflights and stages archive output; the host independently validates and atomically finalizes metadata through immutable CAS plus a SQLite transaction.

**Tech Stack:** Python 3.12+, docker-py low-level API, Pydantic v2, SQLite, SHA-256, zlib CRC-32, pytest, pytest-asyncio, Docker Engine on Ubuntu.

## Global constraints

- Preserve Strix Runner, AgentCoordinator, sessions, budget, resume, and reporting.
- Product Security remains opt-in.
- Reconcile P1 interfaces before P2a.
- Attach only; no mounts, volumes, copy, put/get archive.
- P2a supports TAR/ZIP only.
- Test-first development.
- One focused commit per task.
- No P2b/P2c/P3 work.

---

## Task 1 — Reconcile P1 interfaces and freeze contracts

**Files**

- Create: `docs/product-security/firmware/p2a-interface-reconciliation.md`
- Modify: `strix/domains/product_security/firmware/models.py`
- Modify: `strix/domains/product_security/firmware/repository.py`
- Modify: `strix/domains/product_security/firmware/service.py`
- Test: `tests/domains/product_security/firmware/test_p2a_prerequisites.py`

**Produces**

```python
FirmwareInputArtifact.open_reader() -> BinaryIO
FirmwareRepository.transition_analysis(
    analysis_id: str,
    expected: set[str],
    target: str,
) -> None
FirmwareRepository.commit_verified_output(
    analysis_id: str,
    output: VerifiedWorkerOutput,
) -> None
```

- [ ] Inspect actual P1 names and document `used unchanged`, `wrapped`, or `compatibly extended`.
- [ ] Write failing tests for required analysis states and immutable input reader.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/test_p2a_prerequisites.py -v
```

- [ ] Add only required compatibility methods.
- [ ] Define:

```python
@dataclass(frozen=True, slots=True)
class VerifiedWorkerOutput:
    manifest_bytes: bytes
    manifest: "P2AManifest"
    manifest_sha256: str
    staging_blobs: tuple["VerifiedStagingBlob", ...]
    result: "WorkerResult"
    container_observation: "ContainerObservation"
```

- [ ] Run Product Security tests:

```bash
pytest tests/domains/product_security -q
```

- [ ] Commit:

```bash
git commit -am "docs: reconcile firmware P2a interfaces"
```

---

## Task 2 — FWAP constants, errors, and frame codec

**Files**

- Create: `protocol/constants.py`
- Create: `protocol/errors.py`
- Create: `protocol/frame.py`
- Test: `protocol/test_frame_codec.py`
- Test: `protocol/test_frame_decoder_fuzz.py`

**Produces**

```python
class Frame(BaseModel):
    message_type: MessageType
    flags: FrameFlags
    stream_id: int
    sequence: int
    payload: bytes

class FrameEncoder:
    @staticmethod
    def encode(frame: Frame) -> bytes: ...

class FrameDecoder:
    def feed(self, data: bytes) -> list[Frame]: ...

class FrameSequenceValidator:
    def accept(self, frame: Frame) -> None: ...
```

- [ ] Write exact header test:

```python
def test_header_is_32_bytes():
    encoded = FrameEncoder.encode(
        Frame(
            message_type=MessageType.HELLO,
            flags=FrameFlags.JSON_PAYLOAD,
            stream_id=0,
            sequence=0,
            payload=b"{}",
        )
    )
    assert encoded[:4] == b"FWAP"
    assert len(encoded[:32]) == 32
```

- [ ] Run and confirm import failure.
- [ ] Implement:

```python
HEADER_STRUCT = struct.Struct(">4sBBBBIIQII")
assert HEADER_STRUCT.size == 32
```

- [ ] Use `zlib.crc32(data) & 0xFFFFFFFF`.
- [ ] Validate header before payload allocation.
- [ ] Add one-byte-at-a-time fragmentation test.
- [ ] Add multi-frame read test.
- [ ] Add bad magic/version/flags/CRC/length tests.
- [ ] Add sequence skip/repeat tests.
- [ ] Add deterministic random-byte fuzz ensuring bounded buffer.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/protocol -v
```

- [ ] Commit:

```bash
git commit -am "feat: add FWAP frame codec"
```

---

## Task 3 — Strict JSON message and manifest models

**Files**

- Create: `protocol/messages.py`
- Test: `protocol/test_message_models.py`

**Produces**

`Hello`, `HelloAck`, `AnalysisRequest`, `RequestAccepted`, `InputBegin`, `InputEnd`, `InputAccepted`, `Progress`, `P2AManifest`, `P2AManifestBlob`, `ManifestAccepted`, `BlobBegin`, `BlobEnd`, `WorkerResult`, `WorkerError`, `Cancel`.

- [ ] Write unknown-field rejection test.
- [ ] Write lowercase 64-hex SHA validation test.
- [ ] Write strict integer limit tests.
- [ ] Implement:

```python
class StrictMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
```

- [ ] Implement canonical JSON:

```python
def encode_json_message(message: BaseModel) -> bytes:
    return json.dumps(
        message.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
```

- [ ] Reject BOM and non-object JSON.
- [ ] Add manifest cross-field validation:
  - blob count;
  - total bytes;
  - ordinal continuity;
  - stream ID formula;
  - generated name regex;
  - unique paths;
  - zero-blob status.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/protocol/test_message_models.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add FWAP message schemas"
```

---

## Task 4 — Explicit Host and Worker state machines

**Files**

- Create: `protocol/state.py`
- Test: `protocol/test_protocol_state.py`

**Produces**

```python
class HostStateMachine:
    def accept(self, message_type: MessageType) -> None: ...

class WorkerStateMachine:
    def accept(self, message_type: MessageType) -> None: ...
```

- [ ] Write one complete valid Host flow.
- [ ] Write one complete valid Worker flow.
- [ ] Generate every invalid state/message pair.
- [ ] Run and confirm failure.
- [ ] Implement table-driven transition maps; no permissive default.
- [ ] Verify streaming states allow only declared chunk/progress frames.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/protocol/test_protocol_state.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add FWAP state machines"
```

---

## Task 5 — Docker raw-stream decoder and attach socket

**Files**

- Create: `runtime/docker_attach.py`
- Test: `runtime/test_docker_attach_demux.py`

**Produces**

```python
class DockerRawStreamDecoder:
    def feed(self, data: bytes) -> list[bytes]: ...

class DockerAttachSession(Protocol):
    def write_all(self, data: bytes) -> None: ...
    def read_stdout(self, max_bytes: int) -> bytes: ...
    def shutdown_write(self) -> None: ...
    def close(self) -> None: ...
```

- [ ] Write Docker 8-byte header tests.
- [ ] Cover fragmented headers/payloads and multiple frames.
- [ ] Reject stderr stream type.
- [ ] Reject non-zero reserved bytes.
- [ ] Reject overlimit and truncation.
- [ ] Implement bounded incremental demux.
- [ ] Implement low-level Docker socket wrapper with complete writes.
- [ ] Map socket errors to stable transport errors.
- [ ] Ensure blocking calls do not run on main event loop.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/runtime/test_docker_attach_demux.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add Docker attach transport"
```

---

## Task 6 — Restricted worker image

**Files**

- Create: `docker/firmware-worker/Dockerfile`
- Create: `docker/firmware-worker/seccomp.json`
- Create: `docker/firmware-worker/build-image.sh`
- Create: `docker/firmware-worker/verify-image.py`
- Create: `docker/firmware-worker/worker-image.lock`
- Test: `runtime/test_worker_container_config.py`

- [ ] Resolve a digest-pinned builder image:

```bash
docker pull python:3.12-slim-bookworm
docker image inspect \
  --format '{{index .RepoDigests 0}}' \
  python:3.12-slim-bookworm
```

- [ ] Select a shell-less digest-pinned final runtime.
- [ ] Add static test: every `FROM` contains `@sha256:`.
- [ ] Add static test: final `USER 65532:65532`.
- [ ] Add fixed entrypoint.
- [ ] Add seccomp profile validation.
- [ ] Build script records image and source digest.
- [ ] Verification script proves no shell/package manager and correct identity.
- [ ] Build and verify:

```bash
bash docker/firmware-worker/build-image.sh
python docker/firmware-worker/verify-image.py
```

- [ ] Commit:

```bash
git commit -am "build: add restricted firmware worker image"
```

---

## Task 7 — Container configuration and forced cleanup

**Files**

- Create: `runtime/worker_container.py`
- Test: `runtime/test_worker_container_config.py`
- Test: `runtime/test_worker_launcher.py`

**Produces**

```python
class FirmwareWorkerContainer:
    def create(self) -> None: ...
    def start_and_attach(self) -> DockerAttachSession: ...
    def inspect(self) -> ContainerObservation: ...
    def destroy(self) -> ContainerObservation: ...
```

- [ ] Test exact host config, including empty mounts/devices.
- [ ] Test `MemorySwap == Memory`.
- [ ] Test `Tty=false`, no stderr, `LogDriver=none`.
- [ ] Test labels use trusted scan/analysis IDs.
- [ ] Test `destroy()` is idempotent.
- [ ] Implement immutable spec generation; callers cannot add Docker options.
- [ ] Implement cleanup:
  1. close;
  2. inspect;
  3. kill if running;
  4. wait;
  5. force remove.
- [ ] Run runtime tests.
- [ ] Commit:

```bash
git commit -am "feat: add restricted worker lifecycle"
```

---

## Task 8 — Worker handshake, request, and input staging

**Files**

- Create: `worker/limits.py`
- Create: `worker/staging.py`
- Create: `worker/session.py`
- Test: `worker/test_worker_session.py`

**Produces**

```python
class WorkerLimits(BaseModel): ...
class WorkerStaging: ...
class WorkerSession:
    def run(self, reader: BinaryIO, writer: BinaryIO) -> int: ...
```

- [ ] Write in-memory HELLO and request tests.
- [ ] Write size/hash mismatch tests.
- [ ] Write input overrun and duplicate-input tests.
- [ ] Implement `/work/input.bin` with exclusive create and mode `0600`.
- [ ] Compute SHA-256 and count while receiving.
- [ ] Send `INPUT_ACCEPTED` only after exact match.
- [ ] Initially emit controlled `not_applicable` manifest/result after input.
- [ ] Add static test forbidding `print` in worker modules.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_worker_session.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add firmware worker input session"
```

---

## Task 9 — Archive path policy

**Files**

- Create: `worker/paths.py`
- Test: `worker/test_path_policy.py`

**Produces**

```python
@dataclass(frozen=True, slots=True)
class CanonicalArchivePath:
    display_path: str
    canonical_path: str
    raw_name_b64: str | None
    path_encoding: str | None

def canonicalize_archive_path(name: str) -> CanonicalArchivePath: ...
```

- [ ] Parameterize unsafe names:

```python
@pytest.mark.parametrize(
    "name",
    [
        "/etc/passwd",
        "../etc/passwd",
        "a/../../etc/passwd",
        r"..\etc\passwd",
        r"C:\Windows\system.ini",
        r"\\server\share\file",
        "a\x00b",
    ],
)
def test_unsafe_path_is_rejected(name):
    with pytest.raises(UnsafeArchivePath):
        canonicalize_archive_path(name)
```

- [ ] Test valid repeated separators, `.` removal, Unicode NFC, and case sensitivity.
- [ ] Test `a/./b` collides with `a/b`.
- [ ] Implement Section 14 exactly.
- [ ] Keep module free of filesystem writes.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_path_policy.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add strict archive path policy"
```

---

## Task 10 — Strict TAR adapter

**Files**

- Create: `worker/adapters/base.py`
- Create: `worker/adapters/tar.py`
- Create: `tests/.../fixtures/builders.py`
- Create: `tests/.../fixtures/malicious_archives.py`
- Test: `worker/test_tar_adapter.py`

**Produces**

```python
class ArchiveAdapter(Protocol):
    adapter_id: str
    def preflight(self, input_path: Path, limits: WorkerLimits) -> AdapterPreflight: ...
    def extract(
        self,
        input_path: Path,
        preflight: AdapterPreflight,
        staging: WorkerStaging,
    ) -> AdapterOutput: ...
```

- [ ] Build test archives in Python; do not commit large binaries.
- [ ] Cover valid TAR, TAR.GZ, TAR.XZ, zero-byte file, nested paths.
- [ ] Cover all hostile TAR cases from the test matrix.
- [ ] Run and confirm failure.
- [ ] Implement full member-table preflight.
- [ ] Never use `extract` or `extractall`.
- [ ] Use `extractfile`, generated names, streamed counting, and SHA-256.
- [ ] Clear all output staging on any member failure.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_tar_adapter.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add strict TAR adapter"
```

---

## Task 11 — Strict ZIP adapter

**Files**

- Create: `worker/adapters/zip.py`
- Test: `worker/test_zip_adapter.py`
- Modify fixture builders.

**Produces**

```python
class ZipAdapter:
    adapter_id = "archive/zip-v1"
    def preflight(...) -> AdapterPreflight: ...
    def extract(...) -> AdapterOutput: ...
```

- [ ] Cover stored, deflated, ZIP64, empty and nested files.
- [ ] Cover encrypted, BZIP2, LZMA, unknown method, CRC, unsafe paths, symlink attributes, limits, directory-only, truncation, dishonest sizes.
- [ ] Run and confirm failure.
- [ ] Implement complete central-directory preflight.
- [ ] Reject unsupported entries before export.
- [ ] Stream to generated names and verify CRC, count, SHA-256.
- [ ] Clear complete staging on any failure.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_zip_adapter.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add strict ZIP adapter"
```

---

## Task 12 — Adapter selection, manifest, and blob export

**Files**

- Create: `worker/manifest.py`
- Create: `worker/export.py`
- Modify: `worker/session.py`
- Test: `worker/test_worker_export.py`

**Produces**

```python
def select_archive_adapter(...) -> ArchiveAdapter | LocalStatus: ...
def build_manifest(...) -> P2AManifest: ...

class WorkerExporter:
    def send_manifest_and_blobs(...) -> WorkerResult: ...
```

- [ ] Test TAR-only, ZIP-only, neither, and ambiguous selection.
- [ ] Test safety rejection returns `rejected`.
- [ ] Test deterministic manifest fields.
- [ ] Test no blob frame before `MANIFEST_ACCEPTED`.
- [ ] Implement generated IDs:
  - ordinal `0..N-1`;
  - ID `blob_########`;
  - stream `4096 + ordinal`.
- [ ] Send blobs sequentially with 1 MiB chunks.
- [ ] Re-open staged file read-only and ensure size unchanged.
- [ ] Generate Result counts from actual sent bytes.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_worker_export.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: export P2a manifest and blobs"
```

---

## Task 13 — Worker entrypoint

**Files**

- Create: `worker/__main__.py`
- Modify: `docker/firmware-worker/Dockerfile`
- Test: `worker/test_worker_entrypoint.py`

- [ ] Start local worker subprocess with pipes and verify HELLO_ACK.
- [ ] Assert all stdout decodes as FWAP.
- [ ] Implement fixed `sys.stdin.buffer` / `sys.stdout.buffer`.
- [ ] Do not initialize normal logging handlers.
- [ ] Map expected failures to bounded ERROR frames.
- [ ] Rebuild image and verify.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/worker/test_worker_entrypoint.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: add firmware worker entrypoint"
```

---

## Task 14 — Host manifest validator

**Files**

- Create: `host/manifest_validator.py`
- Test: `host/test_manifest_validator.py`

**Produces**

```python
@dataclass(frozen=True, slots=True)
class ManifestReservation:
    manifest: P2AManifest
    manifest_sha256: str
    blob_count: int
    total_bytes: int
    streams: frozenset[int]

def validate_manifest(
    raw: bytes,
    expected: ExpectedAnalysis,
    limits: HostLimits,
) -> ManifestReservation: ...
```

- [ ] Test valid reservation and exact raw-byte Manifest SHA.
- [ ] Test wrong analysis/input identity.
- [ ] Test limits, duplicate IDs/streams, invalid generated names, invalid paths, status rules.
- [ ] Implement raw hash before parsing.
- [ ] Apply Host limits independently of Worker request.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/host/test_manifest_validator.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: validate P2a manifests"
```

---

## Task 15 — Host staging and output receiver

**Files**

- Create: `host/staging.py`
- Create: `host/output_receiver.py`
- Test: `host/test_output_receiver.py`

**Produces**

```python
@dataclass(frozen=True, slots=True)
class VerifiedStagingBlob:
    blob_id: str
    path: Path
    size_bytes: int
    sha256: str

class HostOutputReceiver:
    def receive(...) -> VerifiedWorkerOutput: ...
```

- [ ] Test valid blobs with fragmented transport.
- [ ] Test undeclared, duplicate, wrong stream, interleaving, overrun, underrun, wrong hash, missing blob.
- [ ] Test result mismatch, result missing, trailing bytes, exit mid-blob.
- [ ] Implement trusted generated staging path.
- [ ] Use exclusive create, mode `0600`, SHA-256, count, fsync.
- [ ] Permit one active blob only.
- [ ] Remove complete staging directory on any exception.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/host/test_output_receiver.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: receive and verify P2a blobs"
```

---

## Task 16 — Final output/container verifier

**Files**

- Create: `host/verifier.py`
- Test: `host/test_host_verifier.py`

**Produces**

```python
def verify_worker_completion(
    output: VerifiedWorkerOutput,
    observation: ContainerObservation,
) -> VerifiedWorkerOutput: ...
```

- [ ] Test exit zero + valid Result.
- [ ] Test OOMKilled.
- [ ] Test non-zero after complete Result.
- [ ] Test zero exit without Result.
- [ ] Test Result/Manifest/count/hash inconsistency.
- [ ] Implement rule: exit code is auxiliary, valid complete protocol is mandatory.
- [ ] OOM always rejects.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/host/test_host_verifier.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: verify P2a worker completion"
```

---

## Task 17 — Launcher, deadlines, cancellation, and concurrency

**Files**

- Create: `runtime/worker_launcher.py`
- Modify: `config.py`
- Modify: `service.py`
- Test: `runtime/test_worker_launcher.py`

**Produces**

```python
class FirmwareWorkerDeadlines(BaseModel): ...
class FirmwareWorkerLauncher:
    async def run(...) -> VerifiedWorkerOutput: ...
```

- [ ] Mock exact normal message sequence.
- [ ] Use fake monotonic clock for every timeout.
- [ ] Test cancellation sends CANCEL, waits 1 second, kills, removes.
- [ ] Test semaphore default capacity one.
- [ ] Implement launcher ownership of container, attach, state machine, input, receiver, deadlines, cleanup.
- [ ] Move blocking Docker work off event loop.
- [ ] Map timeout/protocol/worker/container errors to persistent state.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/runtime/test_worker_launcher.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: orchestrate P2a worker"
```

---

## Task 18 — CAS/SQLite commit and reconciliation

**Files**

- Modify: `repository.py`
- Modify: `service.py`
- Modify: `models.py`
- Test: `integration/test_p2a_reconciliation.py`

- [ ] Test successful state sequence and metadata/CAS linkage.
- [ ] Test idempotent double commit.
- [ ] Simulate crash:
  - after `verified`;
  - after first CAS copy;
  - after all CAS copies;
  - before SQLite commit;
  - after DB commit before staging cleanup.
- [ ] Delete referenced CAS blob and expect `corrupt`.
- [ ] Implement immutable CAS copy and explicit transactions.
- [ ] Implement startup reconciliation table from Section 20.
- [ ] Mark orphans, but do not delete in same pass.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/integration/test_p2a_reconciliation.py -v
```

- [ ] Commit:

```bash
git commit -am "feat: commit and reconcile P2a output"
```

---

## Task 19 — Real Docker TAR/ZIP end-to-end tests

**Files**

- Create: `integration/conftest.py`
- Create: `integration/test_p2a_tar_e2e.py`
- Create: `integration/test_p2a_zip_e2e.py`

- [ ] Add Docker-availability fixture; Ubuntu CI must not skip.
- [ ] Valid TAR:
  - complete state;
  - expected paths;
  - expected hashes;
  - no remaining container.
- [ ] Malicious TAR:
  - rejected;
  - zero committed output blobs;
  - staging removed.
- [ ] Valid ZIP:
  - complete;
  - deterministic metadata.
- [ ] Malicious ZIP:
  - rejected;
  - zero commit.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/integration/test_p2a_tar_e2e.py \
       tests/domains/product_security/firmware/integration/test_p2a_zip_e2e.py -v
```

- [ ] Commit:

```bash
git commit -am "test: add P2a archive workflows"
```

---

## Task 20 — Protocol fault injection and container security

**Files**

- Create: `fixtures/faulty_worker.py`
- Create: `integration/test_p2a_protocol_faults.py`
- Create: `integration/test_p2a_container_security.py`

- [ ] Add test-only faulty modes:
  - bad Magic;
  - bad CRC;
  - skipped sequence;
  - undeclared Blob;
  - truncated frame;
  - missing Result;
  - trailing bytes;
  - wrong hash;
  - stderr;
  - exit mid-Blob.
- [ ] Verify every mode returns expected stable code and commits nothing.
- [ ] Inspect runtime config.
- [ ] Attempt prohibited socket, mount, namespace, ptrace, rootfs write, `/work` execution, device access, privilege escalation.
- [ ] Add small-limit OOM and ENOSPC tests that do not endanger CI host.
- [ ] Verify cleanup after every case.
- [ ] Run:

```bash
pytest tests/domains/product_security/firmware/integration/test_p2a_protocol_faults.py \
       tests/domains/product_security/firmware/integration/test_p2a_container_security.py -v
```

- [ ] Commit:

```bash
git commit -am "test: harden P2a boundary"
```

---

## Task 21 — CI and operator documentation

**Files**

- Create: `docs/product-security/firmware/p2a-protocol.md`
- Create: `docs/product-security/firmware/p2a-operations.md`
- Modify: Ubuntu CI workflow
- Modify: `README.md` only when needed for a documentation link

- [ ] Document image build and digest verification.
- [ ] Document Docker/cgroup/seccomp/AppArmor checks.
- [ ] Document interrupted, verified, committing, corrupt, orphan, and stale-container recovery.
- [ ] Add Ubuntu CI job:
  1. exact checkout;
  2. build image;
  3. verify lock;
  4. protocol/unit tests;
  5. Docker E2E;
  6. full repository suite.
- [ ] Execute every documented command.
- [ ] Commit:

```bash
git commit -am "docs: add P2a operations and CI gates"
```

---

## Task 22 — Full verification and release-readiness record

**Files**

- Create: `docs/product-security/firmware/p2a-verification-record.md`
- Modify only code needed to fix discovered failures.

- [ ] Record repository identity:

```bash
git rev-parse HEAD
git status --short
git branch --show-current
```

- [ ] Record platform:

```bash
python --version
docker version
docker info
uname -a
```

- [ ] Run focused suite:

```bash
pytest tests/domains/product_security/firmware -v
```

- [ ] Run full suite:

```bash
pytest
```

- [ ] Run quality gates:

```bash
ruff check .
mypy strix
pyright
bandit -c pyproject.toml -r strix
```

- [ ] Build package and worker image.
- [ ] Run one E2E and record image digest, user, network, mounts, caps, security options, memory/swap/PIDs/tmpfs/log driver, exit, cleanup.
- [ ] Map every security invariant to implementation, test, and result.
- [ ] Search forbidden mechanisms:

```bash
grep -RInE \
  'put_archive|get_archive|docker cp|binds=|extractall|\.extract\(' \
  strix/domains/product_security/firmware docker/firmware-worker
```

Review every match.

- [ ] Search placeholders/debug output:

```bash
grep -RInE 'TBD|TODO|FIXME|print\(' \
  strix/domains/product_security/firmware \
  docker/firmware-worker
```

Resolve production matches.

- [ ] Write verification record with exact command results, commit SHA, image digest, date, and limitations.
- [ ] Commit:

```bash
git add docs/product-security/firmware/p2a-verification-record.md
git commit -m "docs: record P2a verification"
```

---

# 27. Definition of done

P2a is complete only when:

1. immutable firmware is streamed over Docker attach stdin;
2. no host path reaches Worker;
3. manifest and blobs return over stdout;
4. no mount, volume, copy, or put/get archive is used;
5. Docker stream is demultiplexed before FWAP;
6. exact 32-byte header and strict state machines are implemented;
7. limits are checked before allocation;
8. Worker independently verifies input size and hash;
9. TAR/ZIP are fully preflighted;
10. archive paths never become storage paths;
11. unsupported members reject complete archive;
12. generated names are used internally;
13. Host validates manifest before blobs;
14. Host rehashes all blobs;
15. any mismatch rejects complete run;
16. container matches security config;
17. every run destroys container;
18. Docker logs are disabled;
19. CAS commit is idempotent;
20. SQLite commit is transactional;
21. reconciliation handles interrupted and commit states;
22. OOM, ENOSPC, timeout, cancel, and protocol error are deterministic;
23. no partial blob is accepted;
24. Product Security remains opt-in;
25. existing Strix tests pass;
26. P2a hostile, fault, security, and E2E tests pass;
27. worker image and source digest are recorded;
28. verification record maps every invariant to evidence.

---

# 28. Deferred work

```text
P2b
- Intel HEX
- Motorola S-record
- MBR/GPT
- range/carve infrastructure

P2c
- SquashFS
- EXT2/3/4
- pinned external-tool adapters

P3
- Firmware Analysis Agent
- rules
- evidence grades
- coverage claims
- planner hints
- validation recipes

P4
- ELF triage
- binary inspection
- bounded disassembly
```

None is required for P2a completion.

---

# 29. Codex handoff prompt

```text
Implement the approved Strix Product Security P2a specification in this
document.

Preserve Strix native Runner, AgentCoordinator, session, budget, resume and
report behavior. Product Security remains opt-in.

Work task-by-task. Use test-first development. Do not implement P2b, P2c,
P3, binary analysis, Ghidra, SquashFS, EXT, partition parsing, record
parsing, firmware rules, planner hints or candidate findings.

Before changing code:
1. verify the checkout commit and clean working tree;
2. run the existing test suite;
3. reconcile P1a/P1b interfaces;
4. record exact files to modify.

The only firmware transfer mechanism is Docker attach stdin/stdout using
FWAP. Do not use bind mounts, named volumes, docker cp, put_archive,
get_archive, or host-side archive extraction.

Do not claim completion until:
- focused P2a tests pass;
- the full repository suite passes;
- static quality gates pass;
- the worker image builds and verifies;
- Ubuntu Docker integration tests execute;
- the verification record is complete.
```
