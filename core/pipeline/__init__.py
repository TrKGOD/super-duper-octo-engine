"""End-to-end investigative pipeline (observation → hypothesis → policy → tool → execution →
evidence → independent validation → graph/coverage → next cycle).

The package wires existing, separately tested components; it introduces no new execution path,
no second graph, no second registry and no second validation system. See ``runner.py``.
"""
from core.pipeline.discovery import project_discovery
from core.pipeline.executor import PipelineExecutor
from core.pipeline.identities import IdentityDirectory, IdentityDirectoryError
from core.pipeline.runner import AssessmentPipeline
from core.pipeline.strategies import STRATEGIES, Strategy
from core.pipeline.tools import BROKER_AUTHZ_COMPARE, build_pipeline_registry

__all__ = ["AssessmentPipeline", "PipelineExecutor", "IdentityDirectory", "IdentityDirectoryError",
           "STRATEGIES", "Strategy", "BROKER_AUTHZ_COMPARE", "build_pipeline_registry", "project_discovery"]
