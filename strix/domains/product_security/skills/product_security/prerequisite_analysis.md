---
name: prerequisite_analysis
description: Extract ProductContext facts, inferences, assumptions, and unknowns from product materials.
---

# Prerequisite Analysis

Build `domain/product_context.json` through the domain tools:

1. Call `get_document_manifest` once. The manifest is SHA-256 deduplicated; process each `document_id` once.
2. Call `read_document_text(document_id)` for every manifest entry and keep that ID as the source reference.
3. Extract assets, interfaces, protocols, trust boundaries, data flows, security requirements, threats, assumptions, and unknowns.
4. Give each item a stable semantic ID. Reuse an existing ID for the same item instead of adding a duplicate.
5. Set `basis` to exactly `documented_fact`, `inference`, `assumption`, or `unknown`. Facts and inferences require `source_ref`; never present an inference as a fact.
6. Set confidence from `0.0` to `1.0`, include conflicts and unknowns as assumptions, then call `write_product_context` with the complete JSON payload.
7. Call `get_product_context` and verify the persisted artifact before finishing.
