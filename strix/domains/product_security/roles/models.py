"""Pydantic models for Product Security agent roles."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RoleProfile(BaseModel):
    role_id: str
    display_name: str
    description: str
    skills: list[str] = Field(default_factory=list)
    allowed_tool_names: list[str] = Field(default_factory=list)
    output_artifact_types: list[str] = Field(default_factory=list)
    risk_ceiling: str
    can_spawn_roles: list[str] = Field(default_factory=list)
    inherit_context: bool = True
