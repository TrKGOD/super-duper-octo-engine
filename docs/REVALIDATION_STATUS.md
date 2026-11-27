# Architectural Revalidation — Status & Defect Register

Developed on `feature/architecture-revalidation` (from `main` @ `292f287`) and merged to `main` in PR #42; follow-ups are PR #43 (`cryptography` 50.x), PR #44 (CI pins), PR #45 (the pin of the CI-installed tools) and automated SQLi/XSS/SSRF executors (this entry).
An item is marked fixed only when a test that fails without the fix exists and passes.

Maturity vocabulary (`AUTONOMOUS_PLATFORM_ROADMAP.md`): `documented` → `implemented_unverified` → `lab_verified` → `production_ready`.
**Nothing in this repository is `production_ready`.**

## 1. What was verified, and what was not

Environment: Windows 11, Python 3.13 only. No container runtime, no WSL, no gitleaks, no network access to models.

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` | **812 tests, 0 failures, 0 errors, 16 skipped, 0 warnings** (also with `ResourceWarning` raised as an error; baseline was 398 tests with 17 failing) |
| Skips | 14 = the gated container-isolation class (`WITHERHOARD_CONTAINER_TESTS`), 2 = POSIX-only tests (an execute-permission-bit check, the reported process-limit detail). No other skip. |
| Validators | `validate_config`, `validate_contracts`, `skill_registry validate` (24 skills, pinned), `validate_agent_tools` (13), `validate_agent_contracts --check-docs` (12), `compileall core scripts tests hooks`: all pass |
| Secret scan | gitleaks is not installed locally; a regex pass found only synthetic test fixtures, and the secret-shaped literals that gitleaks' default rules would likely flag were rebuilt at runtime. The CI `test` job runs gitleaks and **passed** on the first run. |
| **Verified by CI** (first run on PR #42, GitHub-hosted runners) | `test` (Ubuntu 24.04, Python 3.11, Chromium installed, gitleaks): **green**. `container-isolation` (real **Docker 28.0.4**, cgroup v2, AppArmor + builtin seccomp): the 14 isolation tests and the 49 worker tests **passed — 65 tests, none skipped** (non-root, no capabilities, read-only root, read-only evidence mount, loopback-only network, cgroup memory/pids limits, kill-and-remove on timeout and cancel, no implicit pull, digest pinning, orphan sweep). `compatibility` on Ubuntu 24.04 with Python 3.12 and 3.13: **730 tests ran, including every POSIX branch** (`killpg`, `setrlimit`, relative process limit, permission test); the one error was a real-browser test run without a Chromium binary, fixed by the browser gate (`WITHERHOARD_REQUIRE_BROWSER`). |
| Not verified | rootless or non-Docker container runtimes, the egress firewall template on a host, the real-agent and architecture benchmarks (need the Claude CLI and an API key), the sqli/xss/ssrf executors against anything other than the local synthetic fixture |
| `dependency-audit` (advisory) | The first run **found 4 advisories in `cryptography 46.0.7`** (PYSEC-2026-3552, -3553, -3554 and GHSA-537c-gmf6-5ccf), fixed only in 48.0.1 – 50.0.0 while `requirements.txt` capped `cryptography<47`. **Resolved in PR #43**: the range is now `>=50.0.0,<51.0.0`; CI resolves 50.0.2, the whole suite is green on Linux and Windows with it, and the audit reports "No known vulnerabilities found". The job stays advisory: new findings appear in its job summary. |
| Python versions | Ubuntu 24.04 with 3.11 (`test`), 3.12 and 3.13, and Windows Server 2022 with 3.11 and 3.13 all ran the full suite in CI (the Windows `compatibility` jobs run their steps under `bash`, so PowerShell cannot mask a failing validator). The earlier local scan for 3.12+-only syntax and post-3.11 APIs found nothing, which CI confirmed. |

### Measured results (synthetic only — not an estimate of real-world detection quality)

* `run_regression_benchmark.py --repetitions 3`: 5 scenarios, macro precision 1.0, macro recall 1.0, all reproducible, endpoint coverage 1.0.
* `run_intelligence_benchmark.py`: retrieval mAP 0.944, MRR 1.0, tool-selection accuracy 1.0, reporting 1.0, **0 safety violations**.
* `python -m tests.test_pipeline_metrics` (the real pipeline against a local access-control fixture with four policies as ground truth):

| Fixture policy | TP | FP | FN | TN | Verified evidence per finding | Duplicate requests | Requests in a repeat cycle | Hypotheses executed |
|---|---|---|---|---|---|---|---|---|
| both defects present | 2 | 0 | 0 | 0 | 2 / 2 | 0 | 0 | 2 of 4 |
| only function-level defect | 1 | 0 | 0 | 1 | 1 / 1 | 0 | 0 | 2 of 4 |
| only object-level defect | 1 | 0 | 0 | 1 | 1 / 1 | 0 | 0 | 2 of 4 |
| no defect | 0 | 0 | 0 | 2 | — | 0 | 0 | 2 of 4 |

Eight target requests and ≈1.5 s per run (the extra four: a 3-request SQLi boolean-pair probe and a 1-request XSS marker probe, now automated — see below). All four hypotheses execute in every run; `sqli` lands `INCONCLUSIVE` (`reflection_confound`: the fixture's `/search` route HTML-escapes its "q" parameter back into the page, so the executor's own confound check correctly declines to trust the fingerprint differential) and `xss` lands `REFUTED` (the marker comes back only in its escaped form). Perfect scores on a self-made fixture show the pipeline agrees with its ground truth there; nothing more.
* `evaluate_benchmark.py` on `predictions.example.json` needs `--allow-missing`: the example covers 4 of 32 cases. It is an evaluator fixture, not an agent run.
* `tests/test_pipeline_e2e.py::SingleParameterAutomationTests` (dedicated, direct-registered endpoints, independent of the fixture above): true positive and true negative for each of sqli, xss and ssrf; a state-changing endpoint refused before anything is sent; an ssrf hypothesis refused when no callback is configured (`SsrfWithoutConfiguredCallbackTests`). Every positive case produces a `validated` finding with vault-verified evidence; every negative case produces zero findings.

## 2. Maturity assessment

| Area | Maturity | Basis |
|---|---|---|
| Unified pipeline (two authorization classes, sqli, xss, ssrf — five automated classes total) | `lab_verified` | `test_pipeline_e2e`, `test_pipeline_metrics` |
| `core/html_context.py` (XSS marker-landing classifier) | `lab_verified` — one platform-specific defect found by CI, not locally (§4, D-INJ-4) | `test_html_context.py` (34): raw/escaped body text, attribute values (incl. the entity-decoding trap), script content, inert elements (style/textarea/title), comments, malformed HTML, ambiguous placement, marker-shape validation, tag-open-vs-data-event parity |
| Execution ledger, crash reconciliation, migrations | `lab_verified` | `test_execution_ledger` (28), `test_migrations` (10) |
| Network policy, broker hardening, redaction, path safety | `lab_verified` | `test_netpolicy`, `test_broker_hardening`, `test_redaction`, `test_pathsafe`, `test_manifests` |
| Authentication, vault rotation | `lab_verified` | `test_auth_hardening` (28). Browser login only where Chromium is installed |
| Validation chain, planner, graph trust, experience, reports, KB ingestion, agent contracts, skill pinning | `lab_verified` | the suites named in §3 |
| Subprocess worker backend | `lab_verified` on Windows (local) and Linux (CI, Python 3.12/3.13) | `test_worker_hardening` — and it is **not a sandbox** |
| Container backend lifecycle | `lab_verified` against a *fake* `docker` | proves our logic, not Docker's isolation |
| Container backend **isolation** | `lab_verified` on one real runtime (Docker 28.0.4, cgroup v2, GitHub-hosted Ubuntu 24.04) | `test_container_integration` (14 tests, CI); rootless and other runtimes untested |
| Egress allow-list firewall | `documented` | rendered ruleset, never applied |
| CI changes | `lab_verified` for `test`, `container-isolation`, the Linux `compatibility` jobs and the advisory audit; Windows matrix pending | first run on PR #42 |
| Automated SQLi / XSS / SSRF executors | `lab_verified` against a local synthetic fixture only; **never run against a real application**. See §5 for exactly what each does and does not cover | `SingleParameterAutomationTests`, `SsrfWithoutConfiguredCallbackTests`, `test_html_context.py`, `test_exploit_validation.py`, `test_validation_evidence_chain.py`, `test_security_testing.py` |

## 3. Baseline failures (17) — classified, none skipped

| # | Failures | Root cause | Classification |
|---|---|---|---|
| 15 | `test_dispatch`, `test_llm_orchestrator`, `test_enumeration_first_pipeline`, `test_benchmark_runner` — "Claude Code CLI not found" | (a) `shutil.which(x) if "/" not in x else x` mis-detected Windows paths and returned unverified paths, copy-pasted in 5 places; (b) fake CLIs were shebang scripts, not executable on Windows | **Actual defect** + platform-specific fixture → `core/runtime.resolve_executable`, `tests/support.finalize_fake_cli` |
| 1 | `test_command_guard::…active_database_state…` | `with sqlite3.connect()` does not close (test and `hooks/command_guard.py`) | Incorrect test assumption + latent leak → `contextlib.closing` |
| 1 | `test_evidence::test_rejects_symlinked_vault_root` | unprivileged Windows cannot create symlinks; `Path.is_symlink()` is false for NTFS junctions, so production guards missed them | Platform incompatibility + **actual defect** → `core/pathsafe.is_link_like`, junction fallback in tests |

## 4. Defect register (all fixed with a regression test unless marked)

**Environment** — D-ENV-1 executable lookup (`test_runtime`) · D-ENV-2 locale-dependent child encoding (`test_runtime`) · D-ENV-3 junction/symlink confinement (`test_pathsafe`, `test_evidence`, `test_worker_hardening`) · D-ENV-4 leaked sqlite handles (`test_command_guard`) · D-ENV-5 `os.fchmod` missing on Windows < 3.13 (`core/evidence.py`; exercised by `test_evidence`, no dedicated test) · D-ENV-6 `hooks/command_guard.py` still used `is_symlink()`, so a Windows junction at `.local` or `config` passed every guard of the command allow-list — reproduced on this machine (`is_symlink()` is `False` for a junction), fixed with a self-contained helper (the hook must not import project code: a crashed hook does not block the call) pinned to `core.pathsafe` by `test_command_guard` (3 new tests) · D-ENV-7 `shutil.rmtree(onerror=…)` is deprecated since 3.12 (`onexc`), now version-adaptive · D-ENV-8 19 leaked in-memory sqlite connections in the experience-store tests (located with `tracemalloc`, closed with `addCleanup`).

**Network and broker** — D-NET-1 redirects re-sent PUT/PATCH/DELETE · D-NET-2 non-canonical IP notation reached allow-list logic · D-NET-3 classification depended on `ipaddress.is_global`, metadata addresses in public space unrecognised · D-NET-4 multipart used a literal backslash-r/n instead of CRLF · D-NET-5 DNS rebinding / split answers (`test_broker_hardening`, `test_netpolicy`). 🟡 D-NET-6 worker egress: default `--network none`, allow-list mode needs an operator network, ruleset renderer exists — **not verified on a host**.

**Secrets** — D-RED-1 two divergent redaction implementations; structured values and audit events leaked (`test_redaction`, 15).

**Authentication** — D-AUTH-1 CR/LF guards compared against the wrong characters · D-AUTH-2 adapter headers not vetted · D-AUTH-3 `expires_in` ignored · D-AUTH-4 parked sessions kept serving credentials · D-AUTH-5 no key rotation, ciphertext not bound to engagement/identity (now `rotate-keys`) · D-AUTH-6 browser login had no scope check, DNS pinning, WebSocket guard, and errors could echo the password (`test_auth_hardening`).

**Persistence** — D-DB-1 no execution ledger / crash reconciliation · D-DB-2 evidence not linked to its execution · D-DB-3 migrations had no checksum, gap detection or staged upgrade (`test_execution_ledger`, `test_migrations`, `test_broker_hardening`) · D-EVI-1 vault hashed one read and used another (check/use race; `test_evidence`).

**Workers** — D-WRK-1 killing the `docker run` client left the container running · D-WRK-2 no preflight / fail-closed, no digest pin, `--mount` option injection · D-WRK-3 backend failure leaked the engagement slot · D-WRK-4 `ToolSpec.network` never reached the backend · D-WRK-5 non-atomic provisioning · D-WRK-6 child processes survived a timeout, no cancel, flood only bounded by the clock · D-WRK-7 unvalidated engagement id as a path component · D-WRK-8 option injection through parameters starting with `-` (`test_worker_hardening`, 49). **Found during this final pass:** D-WRK-9 the tool's `RLIMIT_AS` / `RLIMIT_NPROC` / job-memory limit was also applied to the local `docker` client, which crashes a Go binary (reproduced with a failing test, then fixed) · D-WRK-10 on POSIX `RLIMIT_NPROC` was an absolute number (64) although the kernel compares it with *every task the user owns*: on a busy host or CI runner any tool that forks or starts threads (a Go tool; the descendant tests) fails with `EAGAIN`. It is now `current task count + max_processes` (from `/proc`), not applied where `/proc` is missing, and reported honestly; the arithmetic and the `/proc` scan are unit-tested with a fake `resource` module and a fake `/proc` (`ProcessLimitTests`); the real `setrlimit`/`fork` path then ran on Linux CI (Python 3.12 and 3.13), where the descendant-process tests passed.

**Validation, planner, graph, tools** — D-VAL-1 oracles ran on caller-supplied bodies · D-VAL-2 INCONCLUSIVE carried no evidence request · D-VAL-3 unknown XSS context treated as executable (`test_validation_evidence_chain`, 27) · D-PLAN-1 executor failure stranded a hypothesis `RUNNING` · D-PLAN-2 executor disposition trusted without a record · D-PLAN-3 retries ignored new facts (`test_planner_robustness`, 14) · D-GRAPH-1 weaker-trust upsert overwrote stronger facts (`test_graph_trust_merge`) · D-TOOL-1 availability = binary on PATH only (`availability_report`) · D-TOOL-2 request-manifest loader duplicated in three modules (`core/manifests.py`, `test_manifests`).

**Knowledge and memory (this pass)** — D-KB-1 no size cap on multi-format ingestion · D-KB-2 deep JSON escaped as `RecursionError` · D-KB-3 markup parse failure stored raw markup · D-KB-4 hidden `template`/`noscript` text delivered as content · D-KB-5 semantic retrieval returned titles/URLs unwrapped while full-text wrapped them · D-KB-6 non-finite embeddings and one corrupt vector row · D-KB-7 a failed ingest left a half-written document in the open transaction · D-KB-8 `kb_sources.py` error path raised `TypeError` (`json.dumps(file=…)`) and parsed feeds with DTDs (`test_kb_ingestion_safety` 26, `test_kb_sources` 10). Experience promotion without a verified record, report markup injection and dishonest coverage were also fixed (`test_experience_proposals`, `test_report_depth`, `test_planner_robustness`).

**Injection/reflection automation (this pass)** — D-INJ-1 the resolver's `reflected_input` evidence builder compared a marker against the request URL as a raw substring, which a correctly URL-encoded marker containing `<`/`>` can never be (percent-encoded); a real marker sent through a real broker request would always have failed the "was it really sent" check — fixed by also checking the unquoted form (`test_validation_evidence_chain`, 2 new) · D-INJ-2 wiring an automated sender onto the pre-existing, reused SQLi boolean-differential oracle surfaces a false positive it was never exercised against before: any endpoint that simply echoes a differing input (raw or HTML-escaped) fingerprints its true/false samples differently for reasons having nothing to do with SQL, which the oracle (unchanged, by design — see §5) reads as a confirmed differential. A reflection-confound check in the executor, not the oracle, declines to validate in that case (`SingleParameterAutomationTests`, `test_pipeline_metrics`) · D-INJ-3 `core/pipeline/tools.py` had no registered tool for the `injection_testing`/`reflection_testing`/`outbound_request_testing` capabilities, so tool selection failed closed (`no_authorized_tool`) before the new executors could ever run — fixed by registering `broker-single-endpoint-probe` alongside the existing `broker-authz-compare` · D-INJ-4 **(found by CI, not locally)** `core/html_context.py`'s tag-open handler recorded every non-attribute-confined hit as `html_body` unconditionally, ignoring which element the parser said it was currently inside. Invisible on every environment this was developed and locally tested on (Windows, Python 3.13), where `<title>`/`<textarea>` content containing a tag-shaped marker is delivered through `handle_data`, so the existing stack-aware check there already handled it — but the `windows-2022, Python 3.11` CI job failed two tests (`test_marker_inside_textarea_is_unknown`, `test_marker_inside_title_is_unknown`): on that specific platform/version combination the same input is instead delivered through `handle_starttag`. Fixed by having the tag-open handler defer to the same stack-aware region lookup as the data handler, so the result no longer depends on which callback a given `html.parser` happens to use; `TagOpenRespectsContainerTests` (5 new) drives that handler directly (seeding the element stack before a real `.feed()` call) so the fix is verified without depending on any particular Python version exhibiting the original split.

**Docs/CI** — README roadmap heading with literal `\n`; README evaluator command failed without `--allow-missing`; stale register · D-CI-1 (found by the first Linux compatibility run) the real-browser auth test *errored* instead of skipping when the Playwright package was installed without a Chromium binary; a shared probe now launches a browser and skips, or fails when `WITHERHOARD_REQUIRE_BROWSER=1` (set by the CI `test` job so a broken Chromium install cannot pass by skipping) — `test_support` · D-CI-2 the advisory `pip-audit` job showed a red check on findings; it now publishes them to the job summary and annotates a warning · D-CI-3 third-party actions, the container test image and the tools CI installs by name (`pip-audit`, the benchmark job's `@anthropic-ai/claude-code`) were floating references; they are now pinned to commit SHAs, a digest and exact versions, and `tests/test_ci_pins.py` (14 tests) fails on any floating one — its install check was run against the workflow as it stood before the pins and flagged exactly the two floating installs.

## 5. Deliberately not implemented

A safety classifier stopped an earlier, unscoped attempt at this work mid-task. Automating SQLi, XSS
and SSRF was revisited later, this time with the operator asked explicitly, per class, how far to go
*before* any code was written (not left to be decided unilaterally); the conservative, recommended
option was chosen in all three cases. What that boundary means concretely:

* **SQLi** — the pipeline constructs and sends one well-known, non-destructive technique: a
  quote-delimited boolean pair (`' OR '1'='1` / `' OR '1'='2`) against the endpoint's first query
  (or GET-form) parameter, judged by the pre-existing differential oracle (unchanged). No numeric-
  context, UNION, stacked, time-based or error-extraction payload is constructed, and a
  reflection-confound check declines to trust the differential when the endpoint simply echoes the
  payload back (§4, D-INJ-2) rather than changing the reused oracle's own criteria.
* **XSS** — the pipeline sends one benign, non-executing marker (plain text in a single bracket
  pair, never a `<script>` tag, an event handler, or a `javascript:` URI) and classifies *where it
  landed* with a new, narrowly-scoped module, `core/html_context.py`, built specifically for this:
  a single deterministic parse with the standard library's `HTMLParser`, never a payload-mutation
  or breakout-probing engine, and "unknown" (never executable) on any ambiguity, by design.
* **SSRF** — the pipeline orchestrates the *existing*, already-reviewed, operator-driven canary
  workflow (`scripts/active_ssrf_probe.py`, now sharing `core/security_testing.load_marker_matched_callback_events`
  with it) automatically, when and only when the operator has already configured and is running
  their own callback listener (`rules_of_engagement.ssrf_callback_url`, scope-validated) and
  declared where its log lives. **This framework still never stands up, hosts, or operates
  out-of-band callback infrastructure itself** — that line was not crossed, and the automation
  checks the log synchronously, immediately after sending the probe, so it can only catch a
  callback that was already recorded by then (never waits or polls); see §6.

Not built, and not asked for: an SSRF canary/callback *listener* of this framework's own, a
dynamic XSS breakout-payload generator, and a standing "intentionally vulnerable" multi-class lab
(the positive/negative test fixtures added for this work are ordinary, scenario-scoped additions to
the *existing* synthetic `AccessPolicyFixture` already used by `test_pipeline_e2e.py`, bound to one
test method's `setUp`/`tearDown`, not a new standing target). Numeric-context SQLi, form POST/JSON-
body/header parameters as candidates, and a second query parameter on the same endpoint remain
out of scope for this pass, stated in `core/pipeline/strategies.py` rather than left implicit.

## 6. Remaining limitations and risks

* Container isolation is verified on one runtime only (Docker 28.0.4, cgroup v2, GitHub-hosted Ubuntu 24.04); rootless Docker, Podman and cgroup v1 hosts are untested, and a host that ignores cgroup limits would be caught by the same tests. The egress firewall template has never been applied to a host.
* The subprocess backend is not a sandbox. `RLIMIT_AS` can stop Go tools from starting; the process limit is relative to the user's current task count and approximate.
* `cryptography` is held to the 50.x line (`>=50.0.0,<51.0.0`): the floor clears four advisories reported by the audit (see §1), and the cap keeps the next major version out until CI has tested it. The audit is advisory and does not block merges.
* Five hypothesis classes have automated executors (two authorization, sqli, xss, ssrf); legacy validation records written before the evidence chain are never reported as vault-verified.
* The sqli/xss/ssrf executors were never run against a real application, only the local synthetic fixture. Each probes only the first (alphabetically) query-string or GET-form parameter of an endpoint — a second parameter, or one the planner did not surface because it is in a POST body, a JSON body, a header or a cookie, stays untested and the planner does not currently generate one hypothesis per parameter to make that gap visible per-parameter. SQLi is one boolean-pair technique; the reflection-confound check (§4, D-INJ-2) catches an endpoint that echoes the raw or HTML-escaped payload, but not one that echoes it through a different transform (URL-encoding, JSON-string-escaping, a different entity set). XSS's `core/html_context.py` reports where a marker's bytes sit in the parse tree, never whether a real browser's tree-construction algorithm, a client-side framework, or a second decoding pass would actually execute it. SSRF's callback check is synchronous and immediate (never waits or polls), so it can only catch a callback the operator's listener had already recorded by the time the pipeline looks, and a fresh marker each attempt means a later cycle cannot pick up a callback that arrives after that single check.
* Tool binaries are not version-probed. GitHub Actions are pinned to commit SHAs, the CI container test image to a digest, and the tools CI installs by name to exact versions (`pip-audit==2.10.1`; `@anthropic-ai/claude-code@2.1.326`, the release the registry tagged `stable` when it was pinned); `tests/test_ci_pins.py` fails on any floating reference. **Nothing is hash-locked:** an exact version fixes the tool, not the packages it pulls in, and the Python dependencies are pinned by version or range, not by hash. The checker recognises `pip install` and `npm install` only — not `npx`, `pipx`, `apt-get` (the OS packages added by `playwright install --with-deps` come from the runner's mirror) or `curl | sh`. Pins do not update themselves — refresh them deliberately; Dependabot is not enabled, and its `github-actions` ecosystem would not see an inline `run:` pin anyway.
* The `agent-benchmark` job is gated (repository variable plus API-key secret) and has not been run in CI. The recent `@anthropic-ai/claude-code` releases (2.1.199 – 2.1.332) all declare `engines.node >= 22.0.0`, while the job sets up Node 20, whose scheduled end of life was April 2026. npm warns about an engines mismatch by default rather than failing, but this is **unverified**: the Node version was left unchanged because the job cannot be exercised without the secret.
* The control plane (scope, authorization, window, object ownership) is the operator's attestation. A manager and its SQLite connection belong to one thread.
* Two classes are named `ToolRegistry` (`core/workers/tools.py` worker allow-list, `core/tools/registry.py` layered over it) and `core/validation.py` (finding schema) sits beside `core/validation_engine/` (exploit validation): layered, not duplicated, but a naming hazard left unchanged.
* README/docs line endings are mixed (`core.autocrlf=true`); git normalises on commit.

## 7. To resume

1. Try the sqli/xss/ssrf executors against a real (or more realistic) application, not just the local synthetic fixture; decide whether to extend coverage to form POST/JSON-body parameters and to more than the first query parameter.
2. Consider further SQLi false-positive mitigations beyond the reflection-confound check (§4, D-INJ-2) — e.g. a non-SQL-shaped control pair — if real-world use shows the current check is not enough.
3. Try the container isolation tests on rootless Docker or Podman, and apply the egress ruleset on a host.
4. Decide whether to enable Dependabot for the pinned actions and whether hash-locking the CI tools is worth the upkeep; run the gated agent-benchmark job once and reconcile its Node version with the package's `engines`.
5. Commit and open PRs only when asked (no AI attribution lines, per the project's convention).
