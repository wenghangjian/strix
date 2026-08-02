"""Artifact repository for Product Security run data."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError


ModelT = TypeVar("ModelT", bound=BaseModel)


class ArtifactCorruptionError(RuntimeError):
    """Raised when a persisted domain artifact cannot be loaded."""


class ArtifactRepository:
    def __init__(self, run_dir: Path) -> None:
        self.root = run_dir if run_dir.name == "domain" else run_dir / "domain"

    def write_json(self, relative_path: str, model: BaseModel) -> Path:
        path = self._resolve(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(model.model_dump(mode="json"), ensure_ascii=False, indent=2)
        self._write_text_atomic(path, f"{payload}\n")
        return path

    def write_text(self, relative_path: str, text: str) -> Path:
        path = self._resolve(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write_text_atomic(path, text)
        return path

    def read_text(self, relative_path: str) -> str:
        path = self._resolve(relative_path)
        return path.read_text(encoding="utf-8")

    def read_json(self, relative_path: str, model_type: type[ModelT]) -> ModelT:
        path = self._resolve(relative_path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return model_type.model_validate(raw)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise ArtifactCorruptionError(
                f"Domain artifact '{relative_path}' is unreadable or invalid: {exc}"
            ) from exc

    def _resolve(self, relative_path: str) -> Path:
        candidate = Path(relative_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"Artifact path must stay under domain/: {relative_path}")
        return self.root / candidate

    @staticmethod
    def _write_text_atomic(path: Path, text: str) -> None:
        tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            tmp_path.write_text(text, encoding="utf-8")
            tmp_path.replace(path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
