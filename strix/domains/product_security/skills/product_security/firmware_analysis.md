---
name: firmware_analysis
description: Offline firmware triage guidance for Product Security scans.
---

# Firmware Analysis

Work only with immutable firmware input artifact IDs returned by
`list_firmware_inputs`. Never request or infer host filesystem paths.

Use `start_firmware_analysis` to create or resume the deterministic analysis job,
then inspect its state with `get_firmware_job` or `get_firmware_summary`. In P1 a
job remains queued because no parser worker is available until P2a. Report queued
work as incomplete and preserve the returned limitation; do not describe it as an
executed analysis.

Perform offline-only firmware triage. Do not execute extracted programs or scripts.
