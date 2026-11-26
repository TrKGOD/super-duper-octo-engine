"""Tool Registry & Adapter Framework (Component D).

Extends the Phase 5 worker tool contract with the Intelligence Layer's richer metadata
(category, capabilities, vulnerability classes, execution profile, adapter, parser, honest
availability) and the four execution profiles. The registry never executes anything; every
tool runs through the Phase 5 worker broker via an adapter. RESTRICTED actions are never
auto-selected and always require explicit operator approval.
"""
from core.tools.adapter import AdapterError, BrokeredCommandAdapter, ToolAdapter, ToolResult
from core.tools.catalog import CATALOG, adapter_for, build_default_catalog
from core.tools.observations import (DISPOSITIONS, Observation, ObservationStore,
                                     correlate_to_graph, normalize_tool_result)
from core.tools.parsers import PARSERS, get_parser
from core.tools.selection import CapabilityRequest, ToolSelector
from core.tools.profiles import (ACTIVE_CONTROLLED, AUTO_SELECTABLE, PASSIVE, PROFILES,
                                 ProfileError, ProfilePolicy, RESTRICTED, SAFE,
                                 requires_operator_approval, validate_profile)
from core.tools.registry import STATUSES, ToolDefinition, ToolRegistry, ToolRegistryError

__all__ = [
    "ToolRegistry", "ToolDefinition", "ToolRegistryError", "STATUSES",
    "ProfilePolicy", "ProfileError", "validate_profile", "requires_operator_approval",
    "PROFILES", "AUTO_SELECTABLE", "PASSIVE", "SAFE", "ACTIVE_CONTROLLED", "RESTRICTED",
    "ToolAdapter", "BrokeredCommandAdapter", "ToolResult", "AdapterError",
    "build_default_catalog", "adapter_for", "CATALOG", "PARSERS", "get_parser",
    "Observation", "ObservationStore", "DISPOSITIONS", "normalize_tool_result",
    "correlate_to_graph", "CapabilityRequest", "ToolSelector",
]
