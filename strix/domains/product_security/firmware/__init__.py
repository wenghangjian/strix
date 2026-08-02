"""Firmware analysis domain primitives."""

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.models import (
    FirmwareAccessContext,
    FirmwareAnalysisRecord,
    FirmwareGeometryContract,
    FirmwareInputArtifact,
    FirmwarePermission,
    FirmwareToolResult,
)


__all__ = [
    "FirmwareAccessContext",
    "FirmwareAnalysisRecord",
    "FirmwareDomainError",
    "FirmwareGeometryContract",
    "FirmwareInputArtifact",
    "FirmwarePermission",
    "FirmwareToolResult",
]
