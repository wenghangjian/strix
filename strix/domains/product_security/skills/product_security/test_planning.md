---
name: test_planning
description: Create auditable Product Security TestPath artifacts from context and attack surface.
---

# Test Planning

Create an explicit, resumable Test Plan DAG rather than a TODO list:

1. Call `get_product_context` and `get_attack_surface` before planning.
2. Produce at least five TestPaths when the supplied material supports them. Every path must include a non-empty `source_refs` list, objective, prerequisites, concrete steps, expected control, success condition, risk level, confidence, and recommended role.
3. Link product IDs through `affected_assets`, `threat_refs`, and `requirement_refs`.
4. Use `depends_on` only for existing TestPath IDs and keep the dependency graph acyclic. Set `parallelizable` and `requires_approval` explicitly.
5. Start new paths as `candidate`. Call `write_test_plan`, then `query_test_plan` to verify persistence.
6. Use `update_test_path_status` for transitions; never rewrite status directly. Valid execution flow is `candidate -> ready -> in_progress -> completed`, with `blocked`, `failed`, and `skipped` used only when justified.

Do not create active L2/L3 paths unless the matching policy-gated runtime tools exist. Keep unsupported paths blocked with the missing prerequisite stated clearly.
