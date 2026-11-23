---
name: web-testing-ssrf
description: Review URL-fetching features, destination validation, and safe evidence. Never access cloud metadata or internal services without explicit authorization and a controlled lab.
---

# Server-Side Request Forgery

## Objective
Review URL-fetching features, destination validation, and safe evidence. Never access cloud metadata or internal services without explicit authorization and a controlled lab.
## Preconditions
- Written authorization and explicit scope are available.
- Testing constraints and exclusions are understood.
- Use supplied evidence or an approved isolated lab by default.

## Workflow
1. Identify the relevant asset, feature, identity, and trust boundary.
2. Record what is directly observed before forming a hypothesis.
3. Select the least intrusive test or analysis that can distinguish the hypothesis.
4. Preserve minimal, redacted evidence and its source.
5. Consider false-positive explanations and environmental behavior.
6. Submit candidate findings for independent validation.

## Output
- Asset / component
- Observation
- Hypothesis
- Evidence references
- Preconditions
- Potential impact (not assumed)
- False-positive considerations
- Limitations
- Recommended safe validation

## Safety
Do not perform destructive, stealthy, persistent, denial-of-service, or bulk data-access actions. Stop when scope or authorization is unclear.
