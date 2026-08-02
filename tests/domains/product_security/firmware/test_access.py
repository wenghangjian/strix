from __future__ import annotations

import pytest

from strix.domains.product_security.firmware.access import (
    FirmwareAccessIssuer,
    require_firmware_permission,
)
from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import FirmwarePermission
from strix.domains.product_security.roles.registry import default_role_registry


def test_issuer_uses_live_role_profile_permissions() -> None:
    issuer = FirmwareAccessIssuer(
        scan_id="scan-1",
        allowed_input_artifact_ids={"fw_input_aaaaaaaaaaaaaaaa"},
    )

    access = issuer.issue(
        agent_id="firmware-child",
        role_profile=default_role_registry().get("firmware_analyst"),
    )

    assert access.role_id == "firmware_analyst"
    assert FirmwarePermission.WORKER_EXECUTE in access.permissions
    assert access.allowed_input_artifact_ids == frozenset({"fw_input_aaaaaaaaaaaaaaaa"})


def test_readonly_role_cannot_gain_permission_from_forged_metadata() -> None:
    issuer = FirmwareAccessIssuer(
        scan_id="scan-1",
        allowed_input_artifact_ids={"fw_input_aaaaaaaaaaaaaaaa"},
    )
    forged_metadata = {
        "role_id": "firmware_analyst",
        "permissions": [FirmwarePermission.WORKER_EXECUTE],
    }

    access = issuer.issue(
        agent_id="planner",
        role_profile=default_role_registry().get("test_planner"),
    )

    assert forged_metadata["permissions"] != list(access.permissions)
    assert FirmwarePermission.WORKER_EXECUTE not in access.permissions


def test_permission_check_binds_context_agent_and_input() -> None:
    input_id = "fw_input_aaaaaaaaaaaaaaaa"
    access = FirmwareAccessIssuer(
        scan_id="scan-1",
        allowed_input_artifact_ids={input_id},
    ).issue(
        agent_id="firmware-child",
        role_profile=default_role_registry().get("firmware_analyst"),
    )

    require_firmware_permission(
        {"agent_id": "firmware-child", "firmware_access": access},
        FirmwarePermission.WORKER_EXECUTE,
        input_artifact_id=input_id,
    )

    with pytest.raises(FirmwareDomainError, match="agent identity"):
        require_firmware_permission(
            {"agent_id": "different", "firmware_access": access},
            FirmwarePermission.WORKER_EXECUTE,
            input_artifact_id=input_id,
        )
    with pytest.raises(FirmwareDomainError, match="input artifact"):
        require_firmware_permission(
            {"agent_id": "firmware-child", "firmware_access": access},
            FirmwarePermission.WORKER_EXECUTE,
            input_artifact_id="fw_input_bbbbbbbbbbbbbbbb",
        )


def test_root_access_is_summary_only() -> None:
    access = FirmwareAccessIssuer(scan_id="scan-1").issue_root(agent_id="root")

    assert access.role_id == "root"
    assert access.permissions == frozenset({FirmwarePermission.SUMMARY_READ})
