# Tool Execution Policies

**Component D (part 2).** Status: `lab_verified`. The four execution profiles and the
deterministic policy that authorizes them (`core/tools/profiles.py`). The policy sits
outside any LLM; agents request capabilities, they do not decide their own authorization.

## Profiles (ordered by impact)

1. **PASSIVE** — public data only (passive DNS, certificate transparency, historical URLs);
   no target probing. Always permitted.
2. **SAFE** — controlled, non-destructive discovery (GET/HEAD/OPTIONS), strict rate/response
   limits.
3. **ACTIVE_CONTROLLED** — approved, bounded vulnerability checks and authenticated tests;
   **state-changing** operations require explicit operator approval.
4. **RESTRICTED** — high-impact or destructive actions. **Never auto-selected by an agent**
   and **always** requires explicit operator approval (or an operator allowlist entry).

## ProfilePolicy

`ProfilePolicy(rules_of_engagement).authorize(tool_id, profile, state_changing,
auto_selected, operator_approved)` returns `(allowed, reason)`:

- PASSIVE → always allowed.
- Otherwise the engagement must be `execution_enabled` **and** `authorization_verified`.
- **RESTRICTED** is checked first (it is the hard rule): refused if `auto_selected`; refused
  unless `operator_approved` or the tool is in `approved_restricted_tools`. Explicit approval
  is the special authorization that permits it.
- Non-restricted profiles are capped by the engagement's `max_execution_profile`.
- A state-changing ACTIVE_CONTROLLED action requires `operator_approved`.

## Guarantees (tested)

- A RESTRICTED tool is **never** returned by `select_tools` for an auto-selection, and the
  adapter refuses to execute it before it reaches the broker
  (`test_restricted_never_auto_selected`, `test_restricted_tool_is_refused_before_execution`).
- A state-changing active test needs operator approval
  (`test_state_changing_active_needs_approval`).
- With execution disabled, nothing beyond PASSIVE runs.

These profile checks are in addition to — not a replacement for — the engagement scope and
broker enforcement, which still apply to every request.
