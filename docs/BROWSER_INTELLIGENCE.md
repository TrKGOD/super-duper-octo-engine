# Browser Intelligence Engine

**Phase 1 — foundation.** Status: `lab_verified` for the deterministic engine and the
real-browser driver against synthetic local targets; see *Maturity* below for exactly
what is and is not proven.

The Browser Intelligence Engine turns a modern web application's observable behavior into
a **normalized, deduplicated attack surface**: routes, network endpoints, forms, workflows
and coverage. It complements the existing HTTP/static crawler (`scripts/active_surface.py`)
by seeing what static crawling cannot — SPA client-side routing, history-API navigation,
and live XHR/fetch traffic — while enforcing the *same* engagement scope.

## Design invariants

| Invariant | Where enforced |
|---|---|
| Page content is **untrusted data**; it never changes scope, policy or behavior | `runner.py` (content is only parsed, never executed as instruction); `test_page_content_cannot_change_scope_policy` |
| Scope uses the **same deterministic allowlist as the HTTP broker** — no second policy engine | `core/browser/scope.py` reuses `core.active_executor._validate_request_scope` |
| **No secret leakage**: bodies, cookie values and secret header/query values are never stored | `network.py` (keeps header *names* only; `_strip_sensitive_query`); `test_secret_values_never_appear_in_output` |
| **No out-of-scope navigation or requests**; cross-origin attempts are recorded as blocked | `runner._enqueue`, `runner._ingest_network`; `test_external_navigation_and_requests_are_blocked` |
| **Pause** on human-verification challenges (CAPTCHA/MFA/OTP) | `runner.explore` → `ChallengeRequired`; `test_human_challenge_pauses_exploration` |
| **Discovery only** — never auto-submits state-changing or destructive forms | `forms.py` classification; the runner records, never submits |
| **Bounded** pages/requests/failures | `BrowserBudget`; `test_page_budget_is_bounded` |

## Modules

| Module | Responsibility |
|---|---|
| `core/browser/models.py` | Frozen value records: `NormalizedRoute`, `NetworkObservation`, `Workflow`, `WorkflowStep`. Metadata only. |
| `core/browser/routes.py` | Deterministic path normalization. Every dynamic segment (int, UUID, hex, date, router `:id`/`{id}`/`*`, opaque token) collapses to a single `{id}` placeholder so equivalent resources deduplicate. `RouteSet` accumulates and merges. |
| `core/browser/network.py` | `NetworkIntelligence`: ingests request metadata, strips sensitive query values, keeps header names only, deduplicates by `(method, normalized-path, origin)`. |
| `core/browser/forms.py` | Parses forms from (untrusted) DOM, extracts fields/inputs/hidden/file/validation, and classifies each as `state_changing` / `destructive` (`auto_submit_allowed` is false for either). |
| `core/browser/coverage.py` | `BrowserCoverage`: distinguishes **discovered / visited / captured / forms / workflows / blocked / failed**, per-identity. Progress accounting, not proof of testing. |
| `core/browser/scope.py` | `OriginScope`: DNS-free in-scope check delegating to the broker's allowlist; strips client-side hash fragments before the server-oriented check. |
| `core/browser/runner.py` | `BrowserIntelligenceRunner`: bounded BFS over in-scope routes via an injectable `BrowserDriver`, folding observations into routes/network/forms/coverage. Plus `compare_identity_surfaces` and `merge_surface_sources`. |
| `core/browser/playwright_driver.py` | Optional real driver: headless Chromium, per-request origin guard (aborts out-of-scope), downloads and service workers disabled, bounded timeouts. |

## The driver seam

Browser I/O lives entirely behind `BrowserDriver.navigate(url) -> PageObservation`. This
makes the engine fully testable without a browser (a scripted fake driver drives every
unit/integration test) and lets the real Playwright driver be an **optional dependency**.
A `PageObservation` carries the final URL, status, DOM snapshot, links, client routes,
captured request metadata, observable action labels, and `challenge`/`error` flags — all
untrusted.

## Integration

- **Scope**: identical allowlist to the HTTP broker; a target out of scope for the broker
  is out of scope for the browser.
- **Surface merge**: `merge_surface_sources(browser_report, *others)` unions browser routes
  with HAR/OpenAPI/`active_surface` output, normalizing every source so equivalent
  resources collapse across sources (directive §6.7).
- **Identity comparison**: `compare_identity_surfaces(a, b)` reports *observed* reachability
  differences between two authorized identities — evidence for later access-control
  analysis, never an authorization finding on its own, and never inferred from hidden UI.
- **Authentication**: the real driver accepts `session_headers` (e.g., a cookie produced by
  the Authentication Manager's `PlaywrightAuthRunner`) to browse as an authorized identity.

## Maturity

- `lab_verified` — route normalization/dedup, network capture + redaction, form discovery
  + classification, coverage, scope enforcement, challenge pause, budgets, identity
  comparison and source merge: exercised by `tests/test_browser_intelligence.py`
  (19 deterministic tests) with a scripted driver.
- `lab_verified` (local) — the **real Playwright driver** discovers a pushState route and a
  `fetch` endpoint against a synthetic local SPA (`PlaywrightBrowserDriverE2ETests`). This
  test runs wherever a Chromium binary is available and **skips** otherwise, so standard CI
  (which installs the Playwright package but not browser binaries) skips it rather than
  failing.
- **Not yet built** (follow-up PRs): active workflow *execution* of safe, non-mutating
  flows; richer JS route extraction from bundles/source maps inside the browser; deeper
  multi-role differential capture; persistence of the normalized surface into the
  engagement store and the attack graph (Phase 2).

## Running the optional E2E locally

```
pip install -r requirements-dev.txt
python -m playwright install chromium
python -m unittest tests.test_browser_intelligence.PlaywrightBrowserDriverE2ETests
```
