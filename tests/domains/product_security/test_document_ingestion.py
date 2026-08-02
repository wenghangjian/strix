from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from reportlab.pdfgen import canvas

from strix.domains.product_security.artifacts.models import DocumentManifest
from strix.domains.product_security.artifacts.repository import ArtifactRepository
from strix.domains.product_security.documents.ingestion import (
    DocumentIngestionError,
    ingest_documents,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_ingest_markdown_documents_dedupes_by_sha256(tmp_path: Path) -> None:
    first = tmp_path / "manual.md"
    second = tmp_path / "copy.md"
    first.write_text("# Device Manual\n\nUses Modbus TCP.\n", encoding="utf-8")
    second.write_text(first.read_text(encoding="utf-8"), encoding="utf-8")
    repo = ArtifactRepository(tmp_path / "run")

    manifest = ingest_documents([str(first), str(second)], repo)

    assert len(manifest.documents) == 1
    document = manifest.documents[0]
    assert document.document_id.startswith("doc_")
    extracted = repo.read_text(document.extracted_text_path)
    assert "Uses Modbus TCP." in extracted
    persisted = repo.read_json("documents/manifest.json", DocumentManifest)
    assert persisted == manifest


def test_ingest_pdf_extracts_text(tmp_path: Path) -> None:
    pdf_path = tmp_path / "manual.pdf"
    pdf = canvas.Canvas(str(pdf_path))
    pdf.drawString(72, 720, "Product Security Manual")
    pdf.drawString(72, 700, "Firmware version 1.2.3")
    pdf.save()
    repo = ArtifactRepository(tmp_path / "run")

    manifest = ingest_documents([str(pdf_path)], repo)

    document = manifest.documents[0]
    assert document.content_type == "application/pdf"
    assert "Product Security Manual" in repo.read_text(document.extracted_text_path)


def test_unsupported_document_type_raises_structured_error(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"\x00\x01")

    with pytest.raises(DocumentIngestionError) as exc:
        ingest_documents([str(binary)], ArtifactRepository(tmp_path / "run"))

    assert exc.value.error_code == "UNSUPPORTED_DOCUMENT_TYPE"
    assert str(binary) in exc.value.message
