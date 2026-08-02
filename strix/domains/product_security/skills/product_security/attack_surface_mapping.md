---
name: attack_surface_mapping
description: Compare declared, observed, and delta attack surface for product security scans.
---

# Attack Surface Mapping

1. Call `get_product_context` and treat its stable IDs as the canonical asset/interface/protocol references.
2. Use `query_domain_artifact` for authorized Nmap, HTTP sitemap, firmware, or PCAP metadata supplied to the run.
3. Compare declared and observed surfaces. Record entries as `declared`, `observed`, `undocumented`, or `unexpected`.
4. Include source references and confidence for every entry. Do not treat a connection failure as proof that a service is absent.
5. Call `write_attack_surface` with the complete artifact, then call `get_attack_surface` to verify persistence.
