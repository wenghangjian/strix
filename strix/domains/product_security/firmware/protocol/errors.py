"""Stable failures raised by the FWAP transport boundary."""

from __future__ import annotations

from strix.domains.product_security.firmware.errors import FirmwareDomainError


class FWAPProtocolError(FirmwareDomainError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(error_code, message, retryable=False)
