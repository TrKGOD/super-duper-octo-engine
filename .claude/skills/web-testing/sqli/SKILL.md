---
name: web-testing-sqli
description: Investigate SQL injection hypotheses using query-context reasoning and safe analysis of operator-captured baseline and differential responses.
---

# SQL injection specialist workflow

## Trigger from application context
Select this pack when a feature plausibly constructs a database query from attacker-controlled input: search/filter/sort, report builders, identifiers, nested JSON filters, GraphQL resolvers, legacy parameters, exports, or ORM/raw-query boundaries. Prioritize inputs that reach a query sink and affect a meaningful application behavior. Do not run generic payload lists against every parameter.

## Contextual investigation
1. Trace input source → validation/normalization → query construction or ORM boundary → response/business behavior. Record the database/driver only when evidence supports it.
2. Identify parameter type, encoding, quoting context, expected grammar, query operation and whether the value is actually used in a database query.
3. Prefer code review, query logs, stack traces with secrets redacted, and operator-captured evidence over speculative probing.
4. Compare a baseline with operator-approved synthetic true/false test cases. Keep all requests read-only, low-volume, and limited to synthetic records in an isolated or explicitly authorized environment.
5. Review database error signatures, normalized response fingerprints, status behavior and repeatable timing samples. Normalize dynamic values before comparing; account for caches, rate limiting, application exceptions, network jitter and backend load.
6. A single 500, SQL-looking string, response-length change or slow response is not proof. Require multiple independent indicators and an explanation of the query context.
7. Do not retrieve rows, schema, credentials or database files. Do not use stacked queries, write operations, destructive functions, file/OS access, out-of-band callbacks or deliberate resource exhaustion.

## Deterministic offline analyzer
Store sanitized captures in .local/sqli-pair.json using this shape:
~~~json
{
  "baseline": {"status_code": 200, "body_excerpt": "baseline", "normalized_fingerprint": "same-shape"},
  "true_case": {"status_code": 200, "body_excerpt": "synthetic result", "normalized_fingerprint": "true-shape"},
  "false_case": {"status_code": 200, "body_excerpt": "no result", "normalized_fingerprint": "false-shape"},
  "timing_samples_ms": {"true_case": [120, 125, 118], "false_case": [121, 119, 123]},
  "evidence_refs": ["request-evidence-id", "response-evidence-id"]
}
~~~
Run:
~~~bash
python3 scripts/analyze_protocol_artifacts.py sqli-pair --input .local/sqli-pair.json
~~~
The analyzer only inspects local JSON. It reports SQL error signatures, paired response differences and sufficiently repeated timing differences as candidates. Timing thresholds are heuristic; interpret them with application/server telemetry. It does not generate payloads or transmit requests.

## Active validation boundary
No SQLi-specific active probe runner is currently implemented. If active validation is needed, the operator must approve exact synthetic test cases and request manifests separately; any request must go through the existing scope-enforcing HTTP broker. Do not modify a pinned manifest or invent payloads during execution. Do not bypass the broker with curl, raw sockets, browser automation or third-party scanners.

## Finding standard
Document the exact parameter and feature, evidence of query reachability, baseline/true/false comparison, normalization method, repeatability, database-specific evidence (if known), synthetic-data boundary, evidence references and false-positive analysis. State whether the result is a lead, candidate or independently confirmed issue.
