from __future__ import annotations

import json
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.domains.product_security.roles.registry import default_role_registry
from strix.tools.agents_graph.tools import create_agent, view_agent_graph


def _tool_context(context: dict[str, Any], arguments: dict[str, Any]) -> ToolContext[Any]:
    return ToolContext(
        context=context,
        tool_name="create_agent",
        tool_call_id="call-1",
        tool_arguments=json.dumps(arguments),
    )


@pytest.mark.asyncio
async def test_create_agent_rejects_unknown_role_with_structured_error() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Strix", parent_id=None)
    ctx = _tool_context(
        {
            "coordinator": coordinator,
            "agent_id": "root",
            "spawn_child_agent": lambda **_kwargs: {},
            "product_security_roles": default_role_registry(),
        },
        {
            "name": "Bad Role",
            "task": "test",
            "role": "missing",
        },
    )

    result = json.loads(
        await create_agent.on_invoke_tool(
            ctx,
            ctx.tool_arguments,
        )
    )

    assert result["success"] is False
    assert result["error_code"] == "UNKNOWN_PRODUCT_SECURITY_ROLE"
    assert result["role_id"] == "missing"


@pytest.mark.asyncio
async def test_create_agent_passes_role_to_spawner() -> None:
    calls: list[dict[str, Any]] = []

    async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"success": True, "agent_id": "child", "name": kwargs["name"]}

    coordinator = AgentCoordinator()
    await coordinator.register("root", "Strix", parent_id=None)
    ctx = _tool_context(
        {
            "coordinator": coordinator,
            "agent_id": "root",
            "spawn_child_agent": spawn_child_agent,
            "product_security_roles": default_role_registry(),
        },
        {
            "name": "Firmware Analyst",
            "task": "Analyze firmware",
            "role": "firmware_analyst",
        },
    )

    result = json.loads(
        await create_agent.on_invoke_tool(
            ctx,
            ctx.tool_arguments,
        )
    )

    assert result["success"] is True
    assert calls[0]["role"] == "firmware_analyst"


@pytest.mark.asyncio
async def test_domain_role_cannot_spawn_role_outside_allowlist() -> None:
    calls: list[dict[str, Any]] = []

    async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"success": True, "agent_id": "child", "name": kwargs["name"]}

    coordinator = AgentCoordinator()
    await coordinator.register(
        "firmware-parent",
        "Firmware Analyst",
        parent_id="root",
        metadata={"role_id": "firmware_analyst", "domain": "product_security"},
    )
    ctx = _tool_context(
        {
            "coordinator": coordinator,
            "agent_id": "firmware-parent",
            "spawn_child_agent": spawn_child_agent,
            "product_security_roles": default_role_registry(),
        },
        {
            "name": "Protocol Tester",
            "task": "Run protocol tests",
            "role": "protocol_security_tester",
        },
    )

    result = json.loads(await create_agent.on_invoke_tool(ctx, ctx.tool_arguments))

    assert result["success"] is False
    assert result["error_code"] == "PRODUCT_SECURITY_ROLE_SPAWN_NOT_ALLOWED"
    assert result["parent_role_id"] == "firmware_analyst"
    assert result["role_id"] == "protocol_security_tester"
    assert calls == []


@pytest.mark.asyncio
async def test_domain_role_can_spawn_role_in_allowlist() -> None:
    calls: list[dict[str, Any]] = []

    async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"success": True, "agent_id": "validator", "name": kwargs["name"]}

    coordinator = AgentCoordinator()
    await coordinator.register(
        "firmware-parent",
        "Firmware Analyst",
        parent_id="root",
        metadata={"role_id": "firmware_analyst", "domain": "product_security"},
    )
    ctx = _tool_context(
        {
            "coordinator": coordinator,
            "agent_id": "firmware-parent",
            "spawn_child_agent": spawn_child_agent,
            "product_security_roles": default_role_registry(),
        },
        {
            "name": "Validator",
            "task": "Validate candidate",
            "role": "vulnerability_validator",
        },
    )

    result = json.loads(await create_agent.on_invoke_tool(ctx, ctx.tool_arguments))

    assert result["success"] is True
    assert calls[0]["role"] == "vulnerability_validator"


@pytest.mark.asyncio
async def test_agent_coordinator_snapshots_role_metadata() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register(
        "child",
        "Firmware Analyst",
        parent_id="root",
        task="Analyze firmware",
        skills=["product_security/firmware_analysis"],
        metadata={
            "domain": "product_security",
            "role_id": "firmware_analyst",
            "risk_ceiling": "L1",
        },
    )

    snapshot = await coordinator.snapshot()

    assert snapshot["metadata"]["child"] == {
        "task": "Analyze firmware",
        "skills": ["product_security/firmware_analysis"],
        "domain": "product_security",
        "role_id": "firmware_analyst",
        "risk_ceiling": "L1",
    }


@pytest.mark.asyncio
async def test_view_agent_graph_displays_role_metadata() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Strix", parent_id=None)
    await coordinator.register(
        "child",
        "Firmware Analyst",
        parent_id="root",
        metadata={
            "domain": "product_security",
            "role_id": "firmware_analyst",
            "risk_ceiling": "L1",
        },
    )
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root"},
        tool_name="view_agent_graph",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    result = json.loads(await view_agent_graph.on_invoke_tool(ctx, "{}"))

    assert "role=firmware_analyst" in result["graph_structure"]
    assert "risk=L1" in result["graph_structure"]


@pytest.mark.asyncio
async def test_spawn_child_agent_persists_role_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[dict[str, Any]] = []

    async def fake_start_child_runner(**kwargs: Any) -> None:
        started.append(kwargs)

    monkeypatch.setattr(execution, "_start_child_runner", fake_start_child_runner)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Strix", parent_id=None)
    built: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> object:
        built.append(kwargs)
        return object()

    result = await execution.spawn_child_agent(
        coordinator=coordinator,
        factory=factory,
        agents_db_path=object(),  # type: ignore[arg-type]
        sessions_to_close=[],
        run_config=object(),  # type: ignore[arg-type]
        max_turns=1,
        interactive=False,
        parent_ctx={"agent_id": "root", "product_security_roles": default_role_registry()},
        name="Firmware Analyst",
        task="Analyze firmware",
        skills=[],
        parent_history=[],
        role="firmware_analyst",
    )

    child_id = result["agent_id"]
    snapshot = await coordinator.snapshot()
    assert snapshot["metadata"][child_id]["role_id"] == "firmware_analyst"
    assert snapshot["metadata"][child_id]["domain"] == "product_security"
    assert snapshot["metadata"][child_id]["risk_ceiling"] == "L1"
    assert snapshot["metadata"][child_id]["skills"] == ["product_security/firmware_analysis"]
    assert built[0]["role_profile"].role_id == "firmware_analyst"
    assert started


@pytest.mark.asyncio
async def test_respawn_subagents_restores_role_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_start_child_runner(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(execution, "_start_child_runner", fake_start_child_runner)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Strix", parent_id=None)
    await coordinator.register(
        "child",
        "Firmware Analyst",
        parent_id="root",
        skills=["product_security/firmware_analysis"],
        metadata={
            "domain": "product_security",
            "role_id": "firmware_analyst",
            "risk_ceiling": "L1",
        },
    )
    built: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> object:
        built.append(kwargs)
        return object()

    await execution.respawn_subagents(
        coordinator=coordinator,
        factory=factory,
        agents_db_path=object(),  # type: ignore[arg-type]
        sessions_to_close=[],
        run_config=object(),  # type: ignore[arg-type]
        max_turns=1,
        interactive=False,
        parent_ctx={"agent_id": "root", "product_security_roles": default_role_registry()},
        root_id="root",
    )

    assert built[0]["role_profile"].role_id == "firmware_analyst"
