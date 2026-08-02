---
name: product_security_root
description: Root orchestration guidance for Product Security profile scans.
---

# Product Security Root

Use the native Strix agent graph. Create domain specialists with `create_agent(role="...")` only when the Product Security profile is active.

Run the planning sequence through persisted artifacts:

1. Call `get_document_manifest` and confirm the configured inputs are readable.
2. Create `prerequisite_analyst`, wait for it to finish, then call `get_product_context`.
3. Create `attack_surface_analyst`, wait for it to finish, then call `get_attack_surface`.
4. Create `test_planner`, wait for it to finish, then call `query_test_plan`.
5. Create specialist agents only for ready TestPaths and monitor them through the native Agent Graph.

Do not spawn the next role until the previous artifact can be read successfully. Avoid duplicate work by stable artifact and TestPath IDs. Do not run firmware extraction or active protocol tests unless matching policy-gated tools are available.
