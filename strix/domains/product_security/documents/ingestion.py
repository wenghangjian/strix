"""Deterministic local document ingestion for Product Security."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from pypdf import PdfReader

from strix.domains.product_security.artifacts.models import (
    DocumentArtifact,
    DocumentManifest,
)


if TYPE_CHECKING:
    from strix.domains.product_security.artifacts.repository import ArtifactRepository


_TEXT_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


class DocumentIngestionError(RuntimeError):
    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(message)


def ingest_documents(paths: list[str], repository: ArtifactRepository) -> DocumentManifest:
    documents_by_hash: dict[str, DocumentArtifact] = {}
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            raise DocumentIngestionError(
                "DOCUMENT_NOT_FOUND",
                f"Document does not exist or is not a file: {raw_path}",
            )
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest in documents_by_hash:
            continue
        document_id = f"doc_{digest[:12]}"
        content_type, text = _extract_text(path)
        extracted_text_path = f"documents/extracted/{document_id}.txt"
        repository.write_text(extracted_text_path, text)
        documents_by_hash[digest] = DocumentArtifact(
            document_id=document_id,
            source_path=str(path),
            file_name=path.name,
            content_type=content_type,
            size_bytes=len(content),
            sha256=digest,
            extracted_text_path=extracted_text_path,
        )

    manifest = DocumentManifest(documents=list(documents_by_hash.values()))
    repository.write_json("documents/manifest.json", manifest)
    return manifest


def _extract_text(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix in _TEXT_TYPES:
        return _TEXT_TYPES[suffix], path.read_text(encoding="utf-8")
    if suffix == ".pdf":
        return "application/pdf", _extract_pdf_text(path)
    raise DocumentIngestionError(
        "UNSUPPORTED_DOCUMENT_TYPE",
        f"Unsupported product-security document type: {path}",
    )


def _extract_pdf_text(path: Path) -> str:
    try:
        reader = PdfReader(path)
        parts = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:
        raise DocumentIngestionError(
            "DOCUMENT_PARSE_FAILED",
            f"Failed to parse PDF document: {path}",
        ) from exc
    return "\n".join(part.strip() for part in parts if part.strip())
