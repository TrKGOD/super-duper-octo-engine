---
name: web-testing-xss
description: Analyze source-to-sink flows, contexts, encoding, sanitization, and browser evidence. Do not execute payloads against unapproved targets.
---

# Cross-Site Scripting

## Objective
Analyze source-to-sink flows, contexts, encoding, sanitization, and browser evidence.
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
