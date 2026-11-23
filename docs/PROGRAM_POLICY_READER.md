# Bug bounty program policy reader

## Input

The reader accepts a local UTF-8 Markdown/text copy supplied by the operator. It does not crawl program sites, authenticate, call private APIs, bypass platform controls, or infer permission from a public program listing.

```bash
python scripts/parse_program_policy.py \
  --input .local/program-policy.md \
  --output .local/program-scope-draft.json
```

## Output

The generated profile is always marked:

- `status: draft_unverified`
- `operator_confirmation_required: true`

It includes a SHA-256 of the exact source text, extracted section values, source quote/line references, and explicit ambiguity warnings. It attempts to extract in-scope assets, exclusions, prohibited methods, rate limits, testing windows, data handling, safe harbor, and bounty eligibility.

## Safety contract

- A missing in-scope list means **do not test any asset**.
- Missing exclusions require operator review; do not assume an asset is allowed.
- Missing rate limits mean do not generate traffic.
- Missing prohibited-method rules are treated conservatively: active methods remain prohibited.
- Extracted domains/URLs are untrusted candidate strings, not normalized or approved scope.
- Safe-harbor text is quoted as context, not interpreted as legal advice or verified authorization.
- The output is not consumed automatically by engagement initialization or the dispatcher.

An operator must compare the draft against the official current program policy, confirm exact assets and exclusions, test windows, request limits, prohibited methods, data handling, safe-harbor terms, and bounty eligibility, then separately create an engagement with `execution_enabled=false`. The parser is a document triage aid, not a policy oracle.
