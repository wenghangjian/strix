"""Product Security domain extension."""

from strix.domains.product_security.bootstrap import (
    enable_product_security_domain,
    ingest_configured_documents,
)
from strix.domains.product_security.config import ProductSecurityConfig


__all__ = [
    "ProductSecurityConfig",
    "enable_product_security_domain",
    "ingest_configured_documents",
]
