"""Fixed-stream process entrypoint for the restricted firmware worker."""

from __future__ import annotations

import os
import re
import sys

from strix.domains.product_security.firmware.errors import FirmwareDomainError
from strix.domains.product_security.firmware.worker.session import WorkerSession


WORKER_BUILD_ID_ENV = "STRIX_FIRMWARE_WORKER_BUILD_ID"
_SOURCE_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def run_worker() -> int:
    worker_build_id = os.environ.get(WORKER_BUILD_ID_ENV, "")
    if _SOURCE_DIGEST.fullmatch(worker_build_id) is None:
        return 3

    session = WorkerSession(worker_build_id=worker_build_id)
    try:
        return session.run(sys.stdin.buffer, sys.stdout.buffer)
    except FirmwareDomainError as exc:
        return _emit_error(session, exc, exit_code=2)
    except Exception:  # noqa: BLE001 - process boundary must not leak tracebacks
        internal = FirmwareDomainError(
            "WORKER_INTERNAL_ERROR",
            "Firmware worker encountered an internal error.",
            retryable=False,
        )
        return _emit_error(session, internal, exit_code=3)


def _emit_error(
    session: WorkerSession,
    error: FirmwareDomainError,
    *,
    exit_code: int,
) -> int:
    try:
        session.emit_error(sys.stdout.buffer, error)
    except Exception:  # noqa: BLE001 - broken stdout must terminate silently
        return 3
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run_worker())
