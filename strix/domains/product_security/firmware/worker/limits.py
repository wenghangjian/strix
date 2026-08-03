"""Worker-owned immutable copies of host-requested analysis limits."""

from __future__ import annotations

from pydantic import ConfigDict

from strix.domains.product_security.firmware.protocol.messages import AnalysisLimits


class WorkerLimits(AnalysisLimits):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @classmethod
    def from_analysis_limits(cls, limits: AnalysisLimits) -> WorkerLimits:
        return cls.model_validate(limits.model_dump())
