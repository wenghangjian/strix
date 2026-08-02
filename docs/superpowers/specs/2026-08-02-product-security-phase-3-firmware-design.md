# Product Security Phase 3 Firmware Analysis Design

**Status:** Revised after architecture review

## Goal

Add offline, resume-safe firmware inspection to the opt-in Product Security profile. Imported content is never mounted or executed, and extractor exit codes never determine completeness by themselves.

## Trust Boundary

Firmware parsing runs in a dedicated one-shot container, separate from the normal Strix scan sandbox. The host copies in one immutable input and receives only a JSON manifest plus generated regular-file blobs.

The container has `network=none`, no mounts or devices, all capabilities dropped, `no-new-privileges`, a non-root user without sudo, a read-only root filesystem, bounded `noexec` tmpfs work storage, PID/memory/CPU limits, and a seccomp profile denying mount, namespace, ptrace, module, device, and networking syscalls. It is destroyed after each analysis. The security claim is limited to audited fixed-argument dispatch and container containment; seccomp is not treated as an executable-path allowlist.

The host treats worker output as untrusted. It accepts only generated blob names, rechecks count and size limits, copies without following links, recomputes every SHA-256, validates the JSON schema and parent ranges, and atomically persists the result. Any mismatch rejects the whole staging result.

Ubuntu 22.04 is the Docker host. A separate firmware-worker image uses a digest-pinned Linux base and pinned source/lockfiles; its exact image digest and tool versions form part of the resume key.

## Data Model And Pipeline

A content-addressed `Blob` stores SHA-256, size, and generated storage name. An `ArtifactNode` represents one occurrence and stores its parent, blob ID, depth, selected adapter, observations, attempts, required children, and status. Its typed relation is `input`, `carve`, `normalized`, or `extracted`: only `carve` has a parent byte `source_span`; normalized nodes store logical addresses, while extracted nodes store archive-member or filesystem inode provenance. Identical bytes can therefore be deduplicated without losing lineage.

1. **Observe:** `file` and Binwalk 3.1.0 record advisory signatures only.
2. **Normalize:** validated Intel HEX or S-record inputs become bounded contiguous binary blobs.
3. **Partition:** validated MBR/GPT images produce bounded partition nodes.
4. **Extract:** one preflight-approved archive or filesystem adapter exports generated regular-file blobs.
5. **Inspect:** bounded ELF metadata, strings, configuration, services, and redacted credential candidates are collected.
6. **Verify:** an independent verifier checks attempts and deterministically aggregates required children.

Advisory observations never create required children or change status. Only an adapter that passes strict format preflight may select a range and create required children. Adapter precedence is records, partition table, filesystem, then archive; ambiguous structural matches are reported as `detected_unsupported` rather than tried recursively.

## Supported Formats

### TAR And ZIP

Python adapters preflight the full member table, canonicalize names for metadata, and stream regular members into generated blob IDs. They reject absolute/UNC/drive paths, traversal, normalized-name collisions, links, devices, TAR sparse entries, encrypted ZIPs, unsupported compression, malformed PAX data, and inconsistent declared sizes. ZIP CRCs and actual emitted bytes are verified. ZIP64 is accepted only within global limits. Reservations are charged before and during streaming, and a rejected attempt discards its complete staging tree.

### SquashFS

Pinned `unsquashfs -pf` output is parsed with its version-matched pseudo-file grammar to establish expected regular-file paths and logical bytes before extraction; unparsable entries reject preflight. The verifier walks staging with `lstat`, rejects links and special objects, compares expected and actual totals, and imports generated blobs only after success. Fixtures cover quoted names, newlines, and escaping. There is no `7z` fallback in Phase 3.

### EXT2/3/4

`e2fsck -fn` must pass before export. The adapter rejects unsupported incompatibility features, including encrypted filesystems. A repository-owned helper built against pinned `libext2fs` inventories directories and numeric inodes as length-delimited records containing inode IDs, sizes, modes, and base64 filename bytes; no line-oriented filename parsing is allowed. After global logical-size reservation, pinned `debugfs` dumps regular inodes individually to generated names. Original paths, inode aliases, hard-link relationships, newlines, and non-UTF-8 names remain lossless metadata. The verifier uses `lstat`/no-follow opens and compares expected inode, path, logical-size, and emitted-byte totals. Images are never mounted and journals are never replayed.

### MBR/GPT Raw Disks

The parser supports 512-byte logical sectors; 4096-byte sectors require explicit configuration or a uniquely valid GPT header at LBA1. GPT requires valid header and partition-array CRCs, primary/backup consistency, and in-range usable LBAs. MBR validates signatures and EBR chains; extended and protective entries are containers, not carved siblings. Hybrid MBR is reported unsupported. Every carve satisfies `offset >= 0`, `length > 0`, and `length <= parent_length - offset` before reading. `sfdisk` output may be recorded for diagnostics but is not the authority.

### Intel HEX And Motorola S-record

A streaming record validator is the runtime authority and emits the canonical segment map directly. Lines, records, addresses, decoded bytes, and segments are bounded. Checksums, byte counts, Intel EOF/extended-address/start-address records, S5/S6 counts, and S7/S8/S9 termination are validated. Data after termination, conflicting entry addresses, address overflow, and any overlap are rejected; out-of-order non-overlapping data is sorted. One blob is emitted per contiguous range, so address gaps are never materialized as padding. Pinned `bincopy` is used only for differential tests, where addresses, lengths, entry point, and bytes must exactly match the canonical map.

### Raw NAND/Flash Dumps

Phase 3 uses stable rule IDs. `FLASH_UBI_CRC_SEQUENCE` requires at least two CRC-valid UBI EC headers with valid offsets at one consistent power-of-two erase interval. `FLASH_JFFS2_CRC_SEQUENCE` requires at least two non-overlapping, same-endian JFFS2 node headers with valid magic, aligned bounded length, and header CRC. Either rule yields `detected_unsupported`; one valid header or OOB-like periodicity alone is weak evidence and yields `unclassified`. Geometry guessing and extraction are deferred until a typed, user-supplied geometry contract and positive fixtures are approved.

## Status Aggregation

Each selected adapter first produces a local result:

- `complete`: all adapter postconditions passed and extraction adapters emitted at least one regular file.
- `partial`: useful blobs exist but an integrity/completeness condition failed.
- `failed`: a supported adapter timed out, crashed, or emitted no useful regular file.
- `rejected`: a local safety, range, path, type, or resource rule was violated; its staging tree is discarded.
- `detected_unsupported`: a format passed preflight but has no safe enabled adapter, or structural matches are ambiguous.
- `not_applicable`: no format passed adapter preflight.
- `unclassified`: flash-like input has only weak, non-format observations.

Aggregation is deterministic and never upgrades the local result. A local `rejected`, `partial`, or `failed` remains so. A local `complete` remains complete only when every required-analysis child is `complete` or `not_applicable`; otherwise it becomes `partial`. Produced-file children are inventory edges and do not require recursive analysis unless separately promoted to required-analysis edges. With no useful output, `detected_unsupported`, `not_applicable`, or `unclassified` is retained. Advisory observations do not participate. Directory-only extraction is always `failed`.

## Components And Authorization

- `firmware/models.py`: blob, occurrence node, attempts, limits, findings, and analysis schemas.
- `firmware/formats/`: streaming record, partition, archive, SquashFS, EXT, and flash-observation adapters.
- `firmware/verifier.py`: independent range, path, type, reservation, hash, and status checks.
- `firmware/worker.py`: fixed-argument graph traversal baked into the dedicated image.
- `firmware/container.py`: creates the restricted container and transfers untrusted results.
- `firmware/ingestion.py` and `pipeline.py`: atomic import, persistence, resume, and lifecycle.
- `firmware/tools.py`: analyst-only execution tools and redacted result readers.

Firmware execution tools are not registered on the root agent. Child runtime context carries a trusted `product_security_role_id`, and every execution tool checks it server-side. Generic artifact queries deny `firmware/input`, `firmware/extracted`, and `firmware/blobs`; other roles receive only redacted firmware findings and planner hints.

Binwalk is detection-only. The worker image also pins e2fsprogs, squashfs-tools, `file`, binutils, and the worker source. Runtime executables are invoked only through an audited absolute-path dispatch table with argument arrays; the image contains no shell or package manager.

## Limits

Defaults are 512 MiB input, 1 GiB total logical output, 128 MiB per logical file, 20,000 paths, 20,000 unique blobs, 1,024 partitions, 1,024 normalized segments, recursion depth 3, 180 seconds per adapter, and 30 seconds per inspection command. The one-shot container uses 2 CPUs, 64 PIDs, 4 GiB memory with no swap, and a 2 GiB tmpfs: input plus accepted/current staging is bounded to 1.5 GiB. Parsers stream or memory-map input except pinned Binwalk 3.1.0, which is budgeted one additional input-sized allocation; the remaining memory is headroom for process and metadata overhead. Logical reservations prevent sparse content from bypassing limits; actual writes are counted independently. Resource exhaustion is `rejected` and forces teardown. Tool output and secret previews are bounded and redacted.

The canonical resume key hashes input SHA-256/size, schema version, all limits and geometry configuration, enabled adapters, worker image digest, seccomp/security-policy digest, tool versions, and inspection-rule version. Resume revalidates persisted blob hashes and never reuses an interrupted or uncommitted staging directory.

## Ubuntu Verification Gate

All verification runs on the configured Ubuntu host:

- Inspect container configuration and prove network, mount, loop, privilege escalation, and device attempts fail; unit-test that all orchestrator process launches pass through the absolute-path dispatch table and never use extracted paths as executables or scripts.
- Test exact image/tool versions, a maximum-size Binwalk scan under the 4 GiB cgroup, deterministic OOM/ENOSPC rejection, and clean one-shot teardown after success, timeout, crash, and malformed output.
- Cover TAR/ZIP collisions, encryption, ZIP64, CRC errors, sparse/PAX cases, links, special files, and dishonest sizes.
- Cover EXT2/3/4 corruption, unsupported features, sparse files, hard links, directory-only images, newline/non-UTF-8 filename bytes, and inode/path count mismatches.
- Cover 512/4096 GPT, CRC and backup damage, conventional/extended MBR, hybrid rejection, overlaps, overflow, truncation, and property-tested range arithmetic.
- Cover HEX/S-record checksum, count/control records, overlap, ordering, termination, overflow, large gaps, and streaming limits.
- Cover flash observations without claiming extraction and nested aggregation conflicts without advisory false-positive pollution.
- Run Product Security authorization/disabled-profile tests, resume/idempotency tests, the full repository suite, Ruff, mypy, package build, and dedicated image smoke tests.

## Deferred

UBI/UBIFS, JFFS2, YAFFS, CramFS, vendor encryption, emulation, Ghidra, exploitation, and firmware patching require separate adapters and threat review.
