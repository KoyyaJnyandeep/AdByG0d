import sys

from . import extended_rule_engine as _coverage_rule_engine

# Publish the expanded rule-engine implementation through the canonical import path.
sys.modules.setdefault(__name__ + ".rule_engine", _coverage_rule_engine)

from .rule_engine import Rule, RuleMatch  # noqa: E402
from .scoring_service import RiskScoringService  # noqa: E402
from .delegation_analyzer import DelegationAnalyzer  # noqa: E402
from .acl_analyzer import ACLAnalyzer  # noqa: E402
from .gpo_analyzer import GPOAnalyzer  # noqa: E402
from .trust_analyzer import TrustAnalyzer  # noqa: E402

__all__ = [
    "Rule", "RuleMatch", "RiskScoringService",
    "DelegationAnalyzer", "ACLAnalyzer", "GPOAnalyzer", "TrustAnalyzer",
]
