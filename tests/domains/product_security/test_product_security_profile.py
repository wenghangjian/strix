from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.domains.product_security.bootstrap import (
    enable_product_security_domain,
    ingest_configured_documents,
)
from strix.domains.product_security.config import ProductSecurityConfig
from strix.skills import registered_skill_dirs


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


cli_main = importlib.import_module("strix.interface.main")


def test_bootstrap_is_idempotent_and_registers_skill_dir(tmp_path: Path) -> None:
    config = ProductSecurityConfig(profile="product-security")

    first = enable_product_security_domain(config, tmp_path)
    second = enable_product_security_domain(config, tmp_path)

    assert first.enabled is True
    assert first.role_registry is second.role_registry
    assert first.artifact_repository.root == tmp_path / "domain"
    assert first.skill_dir in registered_skill_dirs()


def test_disabled_profile_does_not_register_domain(tmp_path: Path) -> None:
    config = ProductSecurityConfig(profile=None)

    runtime = enable_product_security_domain(config, tmp_path)

    assert runtime.enabled is False
    assert runtime.root_tools == ()
    assert runtime.role_tools == ()


def test_enabled_profile_splits_root_and_role_firmware_tools(tmp_path: Path) -> None:
    runtime = enable_product_security_domain(
        ProductSecurityConfig(profile="product-security"),
        tmp_path,
    )
    root_expected = {tool.name for tool in runtime.root_tools}
    role_expected = {tool.name for tool in runtime.role_tools}

    root = build_strix_agent(
        name="Strix",
        is_root=True,
        instructions_override="Test root",
        extra_tools=runtime.root_tools,
    )
    child = make_child_factory(extra_tools=runtime.role_tools)(name="Analyst", skills=[])
    default_root = build_strix_agent(
        name="Strix",
        is_root=True,
        instructions_override="Default root",
    )

    assert "get_product_context" in root_expected
    assert "list_firmware_jobs" in root_expected
    assert "start_firmware_analysis" not in root_expected
    assert "start_firmware_analysis" in role_expected
    assert root_expected <= {tool.name for tool in root.tools}
    assert role_expected <= {tool.name for tool in child.tools}
    assert root_expected.isdisjoint({tool.name for tool in default_root.tools})


def test_role_profile_filters_domain_write_tools(tmp_path: Path) -> None:
    runtime = enable_product_security_domain(
        ProductSecurityConfig(profile="product-security"),
        tmp_path,
    )
    factory = make_child_factory(extra_tools=runtime.role_tools)

    prerequisite = factory(
        name="Prerequisite Analyst",
        skills=[],
        role_profile=runtime.role_registry.get("prerequisite_analyst"),
    )
    planner = factory(
        name="Test Planner",
        skills=[],
        role_profile=runtime.role_registry.get("test_planner"),
    )
    prerequisite_tools = {tool.name for tool in prerequisite.tools}
    planner_tools = {tool.name for tool in planner.tools}

    assert "write_product_context" in prerequisite_tools
    assert "write_test_plan" not in prerequisite_tools
    assert "write_test_plan" in planner_tools
    assert "write_product_context" not in planner_tools


def test_bootstrap_ingests_configured_documents(tmp_path: Path) -> None:
    manual = tmp_path / "manual.md"
    manual.write_text("# Manual\n\nModbus TCP is enabled.\n", encoding="utf-8")
    config = ProductSecurityConfig(profile="product-security", documents=[str(manual)])
    runtime = enable_product_security_domain(config, tmp_path / "run")

    manifest = ingest_configured_documents(runtime)

    assert manifest is not None
    assert manifest.documents[0].file_name == "manual.md"
    assert (tmp_path / "run" / "domain" / "documents" / "manifest.json").exists()


def test_config_reads_profile_documents_and_artifacts_from_scan_config() -> None:
    config = ProductSecurityConfig.from_scan_config(
        {
            "profile": "product-security",
            "documents": ["manual.pdf", "threat_model.md"],
            "artifacts": ["firmware.bin"],
        }
    )

    assert config.enabled is True
    assert config.documents == ["manual.pdf", "threat_model.md"]
    assert config.artifacts == ["firmware.bin"]


def test_cli_parses_product_security_profile_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            "192.168.1.100",
            "--profile",
            "product-security",
            "--document",
            "manual.pdf",
            "--document",
            "threat_model.md",
            "--artifact",
            "firmware.bin",
        ],
    )

    args = cli_main.parse_arguments()

    assert args.profile == "product-security"
    assert args.documents == ["manual.pdf", "threat_model.md"]
    assert args.artifacts == ["firmware.bin"]
