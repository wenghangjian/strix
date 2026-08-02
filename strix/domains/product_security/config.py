"""Configuration for the Product Security domain profile."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


PRODUCT_SECURITY_PROFILE = "product-security"


class ProductSecurityConfig(BaseModel):
    """Run-level product security domain configuration."""

    profile: str | None = None
    documents: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return (self.profile or "").strip().lower() == PRODUCT_SECURITY_PROFILE

    @classmethod
    def from_scan_config(cls, scan_config: dict[str, Any]) -> ProductSecurityConfig:
        return cls(
            profile=_optional_str(scan_config.get("profile")),
            documents=_string_list(scan_config.get("documents")),
            artifacts=_string_list(scan_config.get("artifacts")),
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)] if str(value).strip() else []
