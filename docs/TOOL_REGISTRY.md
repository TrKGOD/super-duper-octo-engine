# Tool Registry

**Component D (part 1).** Status: `lab_verified`. The Intelligence Layer's tool registry,
built **on top of** the Phase 5 worker tool contract — not a replacement. It adds the
metadata needed to discover, select and interpret tools, while execution still goes through
the Phase 5 worker broker.

## ToolDefinition

A `ToolDefinition` (`core/tools/registry.py`) wraps a Phase 5 `core/workers/tools.ToolSpec`
(the execution contract: injection-safe argv, timeout, output cap) and adds: category,
version, **capabilities**, **vulnerability_classes**, **execution_profile**,
`state_changing`, risk, network requirement, supported OS, the `binary` to check for
availability, the `adapter` and `parser` ids, an honest **status**, and documentation.

`status` uses the directive's vocabulary: `planned`, `registered`, `adapter_implemented`,
`lab_tested`, `integrated`, `available`, `disabled`, `requires_operator_configuration`. **A
registry entry is never proof a tool is installed.**

## Registry API

`register` / `unregister` / `update` / `get` / `list(category)` / `search` /
`by_capability` / `by_vulnerability_class`; `check_availability` and `check_version`; and
`select_tools`.

- **`check_availability`** is truthful: a built-in tool (no `binary`) is `available`; a tool
  with a `binary` is `available` only if that executable is on `PATH`, otherwise
  `requires_operator_configuration`. A `disabled` tool reports `disabled`.
- **`select_tools`** is the deterministic baseline selection: filter by capability /
  vulnerability class, drop unavailable tools, and authorize each tool's execution profile
  through the `ProfilePolicy` (see TOOL_EXECUTION_POLICIES.md). **RESTRICTED tools are never
  returned for an auto-selection.** It returns the selected tools and a reason for each
  rejection.

## Execution path (no bypass)

The registry never runs anything. Tools run only through a `ToolAdapter`
(TOOL_ADAPTER_DEVELOPMENT.md), which calls the Phase 5 `WorkerManager.execute` — enforcing
the registered-tool allowlist, the injection-safe argv, the isolated workdir and the output
bounds. The registry is not a way around the broker.

## Tests

`tests/test_tool_registry.py` covers capability/class lookup, honest availability, and
deterministic selection that excludes RESTRICTED and unavailable tools.
