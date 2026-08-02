"""Structured failures for firmware analysis services and tools."""

from __future__ import annotations


class FirmwareDomainError(RuntimeError):
    """A stable firmware-domain error safe to expose through typed tools."""

    def __init__(self, error_code: str, message: str, *, retryable: bool) -> None:
        self.error_code = error_code
        self.message = message
        self.retryable = retryable
        super().__init__(message)
