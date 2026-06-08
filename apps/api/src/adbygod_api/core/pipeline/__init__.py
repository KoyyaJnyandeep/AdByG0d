"""
AdByG0d Execution Pipeline
===========================
Module request → CommandPlan → ObfscTransformer → Executor → OutputNormalizer → Parser → Findings

Public surface:
  CommandPlan, CommandStep   — data model
  ObfscTransformer           — wraps/transforms steps before execution
  PipelineExecutor           — runs an (optionally obfuscated) plan
  OutputNormalizer           — strips obfsc artefacts, normalises raw output
"""

from .command_plan import CommandPlan, CommandStep, StepTechnique
from .obfuscation_transformer import ObfscTransformer, ObfscTechnique
from .executor import PipelineExecutor
from .output_normalizer import OutputNormalizer

__all__ = [
    "CommandPlan",
    "CommandStep",
    "StepTechnique",
    "ObfscTransformer",
    "ObfscTechnique",
    "PipelineExecutor",
    "OutputNormalizer",
]
