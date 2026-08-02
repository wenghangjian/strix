"""Document ingestion for Product Security scans."""

from strix.domains.product_security.documents.ingestion import (
    DocumentIngestionError,
    ingest_documents,
)


__all__ = ["DocumentIngestionError", "ingest_documents"]
