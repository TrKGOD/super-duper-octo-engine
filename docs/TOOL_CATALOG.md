# Tool Catalog

**Component E.** Status: `lab_verified` (adapters + parsers); tool binaries are **not
bundled**. This catalog lists the initial, real tool adapters and their **honest** integration
status. A registry entry is never proof a tool is installed.

## Honesty policy

Each tool below has a real command template (injection-safe parameters), the correct
execution profile, and a **real, tested output parser**. Because the binaries are not shipped,
each is registered with status `adapter_implemented` and reports `requires_operator_configuration`
from `check_availability` until the operator installs it and it is proven in a lab. A mock
adapter is not an integration, and a scanner result is a **CANDIDATE**, never a confirmed
finding.

## Initial catalog (`core/tools/catalog.py`)

| Tool | Category | Profile | Capabilities | Parser | Status |
|---|---|---|---|---|---|
| subfinder | recon | PASSIVE | subdomain_discovery, asset_discovery | real | adapter_implemented |
| dnsx | recon | SAFE | dns_resolution | real | adapter_implemented |
| httpx | recon | SAFE | http_probing, technology_fingerprinting | real | adapter_implemented |
| katana | enumeration | SAFE | crawling, route_discovery | real | adapter_implemented |
| ffuf | enumeration | ACTIVE_CONTROLLED | content_discovery, parameter_discovery | real | adapter_implemented |
| nuclei | web | ACTIVE_CONTROLLED | vulnerability_scanning (→ candidates) | real | adapter_implemented |
| dalfox | web | ACTIVE_CONTROLLED | xss_testing (→ candidates) | real | adapter_implemented |

## Status vocabulary

`planned` → `registered` → `adapter_implemented` → `lab_tested` → `integrated` → `available`;
plus `disabled` and `requires_operator_configuration`. The catalog above is
`adapter_implemented`: the adapter and parser exist and are tested, but the binary is not
installed here, so availability is `requires_operator_configuration`.

## Execution

Every tool runs through the Phase 5 worker broker via `adapter_for(definition)` (a
`BrokeredCommandAdapter` wired with the tool's real parser). Profiles are enforced by
`ProfilePolicy`; nuclei/dalfox/ffuf are ACTIVE_CONTROLLED and require an approved engagement,
and no catalog tool is RESTRICTED (so none is auto-selected into destructive territory).

## Tests

`tests/test_tool_adapters.py`: the seven parsers against realistic output (nuclei/dalfox
results marked `CANDIDATE`), catalog honesty (availability is `requires_operator_configuration`,
never fabricated), injection-safe arguments, and one adapter run **end-to-end through the real
broker** with a synthetic stand-in and the real parser.

## Adding a tool

See TOOL_ADAPTER_DEVELOPMENT.md. In short: add a `ToolSpec` (real command + injection-safe
params), a parser (`core/tools/parsers.py`), and a `ToolDefinition` with the right profile,
capabilities and `binary`; register it; keep its status honest until it is lab-tested.
