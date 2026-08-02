from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.domains.product_security.artifacts.models import ProductContext
from strix.domains.product_security.artifacts.repository import (
    ArtifactCorruptionError,
    ArtifactRepository,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_product_context_is_written_atomically_with_schema_version(tmp_path: Path) -> None:
    repo = ArtifactRepository(tmp_path)
    ctx = ProductContext(project_id="demo", product_name="Controller")

    path = repo.write_json("product_context.json", ctx)

    assert path == tmp_path / "domain" / "product_context.json"
    assert repo.read_json("product_context.json", ProductContext) == ctx
    assert not list((tmp_path / "domain").glob("*.tmp"))


def test_corrupt_artifact_raises_clear_error(tmp_path: Path) -> None:
    repo = ArtifactRepository(tmp_path)
    path = tmp_path / "domain" / "product_context.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ArtifactCorruptionError, match=r"product_context\.json"):
        repo.read_json("product_context.json", ProductContext)
