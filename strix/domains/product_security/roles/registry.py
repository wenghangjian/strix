"""Role registry for Product Security child-agent profiles."""

from __future__ import annotations

from functools import lru_cache

from strix.domains.product_security.roles.models import RoleProfile


class UnknownRoleError(ValueError):
    """Raised when a Product Security role ID is not registered."""

    def __init__(self, role_id: str, available_roles: list[str]) -> None:
        self.role_id = role_id
        self.available_roles = available_roles
        super().__init__(
            f"Unknown product security role '{role_id}'. "
            f"Available roles: {', '.join(available_roles)}"
        )


class RoleRegistry:
    def __init__(self, roles: list[RoleProfile]) -> None:
        self._roles = {role.role_id: role for role in roles}

    def get(self, role_id: str) -> RoleProfile:
        try:
            return self._roles[role_id]
        except KeyError as exc:
            raise UnknownRoleError(role_id, sorted(self._roles)) from exc

    def as_context_map(self) -> dict[str, RoleProfile]:
        return dict(self._roles)


@lru_cache(maxsize=1)
def default_role_registry() -> RoleRegistry:
    return RoleRegistry(
        [
            RoleProfile(
                role_id="prerequisite_analyst",
                display_name="Prerequisite Analyst",
                description=(
                    "Extracts documented product context, requirements, threats, and unknowns."
                ),
                skills=["product_security/prerequisite_analysis"],
                allowed_tool_names=[
                    "get_document_manifest",
                    "read_document_text",
                    "query_domain_artifact",
                    "get_product_context",
                    "write_product_context",
                    "create_evidence",
                    "list_firmware_jobs",
                    "get_firmware_summary",
                ],
                output_artifact_types=["product_context"],
                risk_ceiling="L0",
                can_spawn_roles=["attack_surface_analyst", "test_planner"],
            ),
            RoleProfile(
                role_id="attack_surface_analyst",
                display_name="Attack Surface Analyst",
                description="Compares declared and observed product attack surface.",
                skills=["product_security/attack_surface_mapping"],
                allowed_tool_names=[
                    "get_product_context",
                    "query_domain_artifact",
                    "get_attack_surface",
                    "write_attack_surface",
                    "create_evidence",
                    "list_firmware_jobs",
                    "get_firmware_summary",
                ],
                output_artifact_types=["attack_surface"],
                risk_ceiling="L1",
                can_spawn_roles=["test_planner"],
            ),
            RoleProfile(
                role_id="test_planner",
                display_name="Test Planner",
                description="Builds auditable product-security test paths from domain artifacts.",
                skills=["product_security/test_planning"],
                allowed_tool_names=[
                    "get_product_context",
                    "get_attack_surface",
                    "query_test_plan",
                    "write_test_plan",
                    "update_test_path_status",
                    "list_firmware_jobs",
                    "get_firmware_summary",
                ],
                output_artifact_types=["test_plan"],
                risk_ceiling="L1",
                can_spawn_roles=[
                    "firmware_analyst",
                    "protocol_security_tester",
                    "vulnerability_validator",
                ],
            ),
            RoleProfile(
                role_id="firmware_analyst",
                display_name="Firmware Analyst",
                description="Performs offline firmware triage and reports structured findings.",
                skills=["product_security/firmware_analysis"],
                allowed_tool_names=[
                    "list_firmware_inputs",
                    "get_firmware_job",
                    "get_firmware_summary",
                    "start_firmware_analysis",
                    "create_evidence",
                ],
                output_artifact_types=["firmware_analysis", "firmware_manifest"],
                risk_ceiling="L1",
                can_spawn_roles=["test_planner", "vulnerability_validator"],
            ),
            RoleProfile(
                role_id="protocol_security_tester",
                display_name="Protocol Security Tester",
                description="Runs policy-gated protocol checks through typed adapters.",
                skills=["product_security/protocol_security"],
                allowed_tool_names=[
                    "protocol_discover",
                    "protocol_identify",
                    "protocol_read_state",
                    "create_evidence",
                    "list_firmware_jobs",
                    "get_firmware_summary",
                ],
                output_artifact_types=["protocol_evidence"],
                risk_ceiling="L2",
                can_spawn_roles=["vulnerability_validator"],
            ),
            RoleProfile(
                role_id="vulnerability_validator",
                display_name="Vulnerability Validator",
                description="Reproduces candidates, runs controls, and advances finding lifecycle.",
                skills=["product_security/vulnerability_validation"],
                allowed_tool_names=[
                    "query_domain_artifact",
                    "create_evidence",
                    "update_finding_status",
                    "list_firmware_jobs",
                    "get_firmware_summary",
                ],
                output_artifact_types=["finding"],
                risk_ceiling="L2",
                can_spawn_roles=[],
            ),
        ]
    )
