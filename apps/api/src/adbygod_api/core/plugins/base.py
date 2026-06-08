from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from adbygod_api.models import Finding
from sqlalchemy.ext.asyncio import AsyncSession


class BaseModule(ABC):
    """
    Standard interface for all AdByG0d Assessment Modules.
    Modules can be Collectors (data gathering) or Analyzers (rule processing).
    """

    def __init__(self, assessment_id: str, db: AsyncSession):
        self.assessment_id = assessment_id
        self.db = db

    @property
    @abstractmethod
    def module_id(self) -> str:
        """Unique identifier for the module (e.g., 'kerberos', 'adcs')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""
        pass

    @abstractmethod
    async def run(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the module logic."""
        pass


class CollectorPlugin(BaseModule):
    """Plugins that perform data collection against AD protocols (LDAP, SMB, etc)."""

    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """Gather raw evidence."""
        pass


class AnalyzerPlugin(BaseModule):
    """Plugins that process normalized graph data to produce findings."""

    @abstractmethod
    def analyze(self, graph_data: Dict[str, Any]) -> List[Finding]:
        """Evaluate rules and return findings."""
        pass
