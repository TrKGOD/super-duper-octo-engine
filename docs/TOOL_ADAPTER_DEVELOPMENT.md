# Tool Adapter Development

**Component D (part 3).** Status: `lab_verified`. How to add a tool adapter. An adapter is
the only thing that runs a tool, and it must run it **through the Phase 5 worker broker**.

## The contract (`core/tools/adapter.py`)

A `ToolAdapter` implements the lifecycle (directive §5.2):

1. **Authorize the profile** via `ProfilePolicy` (refuse RESTRICTED auto-selection, require
   approval where needed).
2. **Validate input** — reuse `definition.spec.build_argv(params)`, the Phase 5 injection-safe
   argv validation (a parameter value becomes exactly one argv element; it can never inject
   arguments).
3. **Execute through the broker** — `WorkerManager.execute(worker, spec.tool_id, params,
   allowed_tools=…)`. The broker enforces the registered-tool allowlist, the isolated workdir,
   the timeout and the output ceiling. The adapter registers the tool's worker spec with the
   broker registry if needed; it never builds a shell command or runs a binary directly.
4. **Capture and parse** — turn the (bounded, captured) output into structured observations
   via the adapter's `parse`.
5. **Return** a `ToolResult` (exit status, timing, truncation, the output artifact reference,
   and the parsed observations).

## Writing an adapter

Most tools need only the default `BrokeredCommandAdapter` with a **parser**: a pure
`raw_output -> list[observation]` function. The parser must treat tool output as untrusted
data and extract only structured fields (hosts, endpoints, parameters, candidate findings) —
it must never execute or trust embedded instructions, and a parsed candidate is a
**CANDIDATE**, not a confirmed finding (confirmation is the validation engine's job).

```
adapter = BrokeredCommandAdapter(parser=my_parser)
result = adapter.execute(worker_manager, worker, tool_definition, params,
                         allowed_tools=[tool_definition.spec.tool_id],
                         policy=ProfilePolicy(engagement_rules))
```

## Rules

- No raw shell, ever. No path around `WorkerManager`/the HTTP broker.
- Arguments go through `ToolSpec.build_argv` — never string concatenation of untrusted input.
- Declare the correct execution profile and `state_changing` flag; the policy depends on them.
- Be honest about availability and status; a mock adapter is not an integration (that is why
  the real tool catalog lands incrementally in Component E with per-tool status).

## Tests

`tests/test_tool_registry.py::AdapterExecutionTests` runs a synthetic tool end-to-end through
the real broker and parses its output, refuses a RESTRICTED tool before execution, and shows
the adapter cannot bypass the broker's allowlist.
