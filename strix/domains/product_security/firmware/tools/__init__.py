"""Authorized typed tools for P1 firmware analysis."""

from strix.domains.product_security.firmware.tools.execution import (
    start_firmware_analysis,
)
from strix.domains.product_security.firmware.tools.query import (
    get_firmware_job,
    get_firmware_summary,
    list_firmware_inputs,
    list_firmware_jobs,
)


FIRMWARE_ROOT_TOOLS = (
    list_firmware_jobs,
    get_firmware_summary,
)
FIRMWARE_ROLE_TOOLS = (
    list_firmware_inputs,
    get_firmware_job,
    get_firmware_summary,
    list_firmware_jobs,
    start_firmware_analysis,
)

__all__ = [
    "FIRMWARE_ROLE_TOOLS",
    "FIRMWARE_ROOT_TOOLS",
    "get_firmware_job",
    "get_firmware_summary",
    "list_firmware_inputs",
    "list_firmware_jobs",
    "start_firmware_analysis",
]
