import logging
from typing import Any, Dict, Optional

from adbygod_api.core.plugins.base import AnalyzerPlugin

log = logging.getLogger(__name__)


class PersistenceAnalyzer(AnalyzerPlugin):
    """Detects AD persistence indicators: Shadow Credentials, SID History."""

    @property
    def module_id(self) -> str:
        return "persistence"

    @property
    def name(self) -> str:
        return "Persistence Analysis"

    async def run(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        log.info("Running %s for assessment %s", self.name, self.assessment_id)
        findings = []

        try:
            from adbygod_api.database import AsyncSessionLocal
            from sqlalchemy import select
            from adbygod_api.models import Entity

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(Entity).where(Entity.assessment_id == self.assessment_id)
                )
                entities = result.scalars().all()

            for ent in entities:
                attrs = ent.attributes or {}
                if attrs.get("shadow_credentials"):
                    findings.append({
                        "type": "SHADOW_CREDENTIALS",
                        "sam": ent.sam_account_name,
                        "dn": ent.distinguished_name,
                    })
                if attrs.get("has_sid_history"):
                    findings.append({
                        "type": "SID_HISTORY_POPULATED",
                        "sam": ent.sam_account_name,
                        "sid_history": attrs.get("sid_history", []),
                    })
        except Exception as exc:
            log.warning("PersistenceAnalyzer run error: %s", exc)

        return {"status": "success", "findings_count": len(findings), "findings": findings}
