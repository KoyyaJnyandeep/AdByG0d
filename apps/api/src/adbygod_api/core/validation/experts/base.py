from __future__ import annotations
from abc import ABC
from adbygod_api.core.validation.contracts import ExpertDecision
from adbygod_api.core.validation.context import ValidationAssessmentContext


class BaseExpert(ABC):  # noqa: B024
    expert_id: str = ""
    expert_name: str = ""

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        """Sync evaluation — override this OR override analyze()."""
        raise NotImplementedError

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        """Async entry point used by consensus engine V2.
        Default: wraps sync evaluate(). New experts can override directly."""
        module_id = getattr(self, 'module_id', '')
        try:
            return self.evaluate(module_id, ctx)
        except NotImplementedError:
            # Subclass must implement analyze() directly
            raise
