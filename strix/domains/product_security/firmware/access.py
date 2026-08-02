"""Runner-issued firmware permissions and server-side authorization checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAccessContext,
    FirmwarePermission,
)


if TYPE_CHECKING:
    from strix.domains.product_security.roles.models import RoleProfile


_SUMMARY_ONLY = frozenset({FirmwarePermission.SUMMARY_READ})
_ROLE_PERMISSIONS: dict[str, frozenset[FirmwarePermission]] = {
    "prerequisite_analyst": _SUMMARY_ONLY,
    "attack_surface_analyst": _SUMMARY_ONLY,
    "test_planner": _SUMMARY_ONLY,
    "protocol_security_tester": _SUMMARY_ONLY,
    "vulnerability_validator": frozenset(
        {FirmwarePermission.SUMMARY_READ, FirmwarePermission.METADATA_READ}
    ),
    "firmware_analyst": frozenset(
        {
            FirmwarePermission.SUMMARY_READ,
            FirmwarePermission.METADATA_READ,
            FirmwarePermission.CONTENT_PREVIEW,
            FirmwarePermission.SECRET_FINGERPRINT_READ,
            FirmwarePermission.WORKER_EXECUTE,
            FirmwarePermission.BINARY_INSPECT,
            FirmwarePermission.BINARY_DISASSEMBLE,
            FirmwarePermission.HINT_CREATE,
            FirmwarePermission.RECIPE_CREATE,
            FirmwarePermission.CANDIDATE_CREATE,
        }
    ),
}


class FirmwareAccessIssuer:
    """Issue immutable access contexts from trusted run and role state."""

    def __init__(
        self,
        *,
        scan_id: str,
        allowed_input_artifact_ids: set[str] | frozenset[str] = frozenset(),
    ) -> None:
        self.scan_id = scan_id
        self.allowed_input_artifact_ids = frozenset(allowed_input_artifact_ids)

    def issue(
        self,
        *,
        agent_id: str,
        role_profile: RoleProfile,
    ) -> FirmwareAccessContext:
        permissions = _ROLE_PERMISSIONS.get(role_profile.role_id, frozenset())
        return FirmwareAccessContext(
            scan_id=self.scan_id,
            agent_id=agent_id,
            role_id=role_profile.role_id,
            allowed_input_artifact_ids=self.allowed_input_artifact_ids,
            permissions=permissions,
            access_profile=f"{role_profile.role_id}-v1",
            issued_by="scan_runner",
        )

    def issue_root(self, *, agent_id: str) -> FirmwareAccessContext:
        return FirmwareAccessContext(
            scan_id=self.scan_id,
            agent_id=agent_id,
            role_id="root",
            allowed_input_artifact_ids=self.allowed_input_artifact_ids,
            permissions=_SUMMARY_ONLY,
            access_profile="firmware-root-summary-v1",
            issued_by="scan_runner",
        )


def require_firmware_permission(
    context: object,
    permission: FirmwarePermission,
    *,
    input_artifact_id: str | None = None,
) -> FirmwareAccessContext:
    if isinstance(context, dict):
        inner = cast("dict[str, object]", context)
    else:
        raw_context = cast("object", getattr(context, "context", None))
        inner = (
            cast("dict[str, object]", raw_context)
            if isinstance(raw_context, dict)
            else {}
        )
    access = inner.get("firmware_access")
    agent_id = inner.get("agent_id")
    if not isinstance(access, FirmwareAccessContext):
        raise _access_denied("Trusted firmware access context is missing.")
    if agent_id != access.agent_id:
        raise _access_denied("Firmware agent identity does not match its access context.")
    if permission not in access.permissions:
        raise _access_denied(f"Firmware permission '{permission}' is not granted.")
    if (
        input_artifact_id is not None
        and input_artifact_id not in access.allowed_input_artifact_ids
    ):
        raise _access_denied("Firmware input artifact is not authorized for this agent.")
    return access


def _access_denied(message: str) -> FirmwareDomainError:
    return FirmwareDomainError(
        "FIRMWARE_ACCESS_DENIED",
        message,
        retryable=False,
    )
