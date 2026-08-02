from __future__ import annotations

import pytest

from strix.domains.product_security.roles.registry import UnknownRoleError, default_role_registry


def test_default_registry_contains_phase_one_roles() -> None:
    registry = default_role_registry()

    assert registry.get("firmware_analyst").display_name == "Firmware Analyst"
    assert registry.get("firmware_analyst").risk_ceiling == "L1"
    assert "product_security/firmware_analysis" in registry.get("firmware_analyst").skills


def test_unknown_role_error_is_structured() -> None:
    registry = default_role_registry()

    with pytest.raises(UnknownRoleError) as exc:
        registry.get("missing_role")

    assert exc.value.role_id == "missing_role"
    assert "missing_role" in str(exc.value)
