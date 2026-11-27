# Architectural Revalidation — Status & Defect Register

Branch `feature/architecture-revalidation` (from `main` @ `292f287`). **Nothing is committed or pushed.**
An item is marked fixed only when a test that fails without the fix exists and passes.

Maturity vocabulary (`AUTONOMOUS_PLATFORM_ROADMAP.md`): `documented` → `implemented_unverified` → `lab_verified` → `production_ready`.
**Nothing in this repository is `production_ready`.**

## 1. What was verified, and what was not

Environment: Windows 11, Python 3.13 only. No container runtime, no WSL, no gitleaks, no network access to models.

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` | **736 tests, 0 failures, 0 errors, 16 skipped, 0 warnings** with default warning filters (baseline was 398 tests with 17 failing) |
| Skips | 14 = the gated container-isolation class (`WITHERHOARD_CONTAINER_TESTS`), 2 = POSIX-only tests (an execute-permission-bit check, the reported process-limit detail). No other skip. |
| Validators | `validate_config`, `validate_contracts`, `skill_registry validate` (24 skills, pinned), `validate_agent_tools` (13), `validate_agent_contracts --check-docs` (12), `compileall core scripts tests hooks`: all pass |
| Secret scan | gitleaks is not installed locally; a regex pass found only synthetic test fixtures, and the secret-shaped literals that gitleaks' default rules would likely flag were rebuilt at runtime. The CI `test` job runs gitleaks and **passed** on the first run. |
| **Verified by CI** (first run on PR #42, GitHub-hosted runners) | `test` (Ubuntu 24.04, Python 3.11, Chromium installed, gitleaks): **green**. `container-isolation` (real **Docker 28.0.4**, cgroup v2, AppArmor + builtin seccomp): the 14 isolation tests and the 49 worker tests **passed — 65 tests, none skipped** (non-root, no capabilities, read-only root, read-only evidence mount, loopback-only network, cgroup memory/pids limits, kill-and-remove on timeout and cancel, no implicit pull, digest pinning, orphan sweep). `compatibility` on Ubuntu 24.04 with Python 3.12 and 3.13: **730 tests ran, including every POSIX branch** (`killpg`, `setrlimit`, relative process limit, permission test); the one error was a real-browser test run without a Chromium binary, fixed by the browser gate (`WITHERHOARD_REQUIRE_BROWSER`). |
| Not verified | rootless or non-Docker container runtimes, the egress firewall template on a host, the real-agent and architecture benchmarks (need the Claude CLI and an API key) |
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

Four target requests and ≈0.8 s per run. The two hypotheses never executed in every run are `sqli` and `xss` (no automated executor): they are reported as not executed, not as clean. Perfect scores on a self-made fixture show the pipeline agrees with its ground truth there; nothing more.
* `evaluate_benchmark.py` on `predictions.example.json` needs `--allow-missing`: the example covers 4 of 32 cases. It is an evaluator fixture, not an agent run.

## 2. Maturity assessment

| Area | Maturity | Basis |
|---|---|---|
| Unified pipeline (two authorization classes) | `lab_verified` | `test_pipeline_e2e`, `test_pipeline_metrics` |
| Execution ledger, crash reconciliation, migrations | `lab_verified` | `test_execution_ledger` (28), `test_migrations` (10) |
| Network policy, broker hardening, redaction, path safety | `lab_verified` | `test_netpolicy`, `test_broker_hardening`, `test_redaction`, `test_pathsafe`, `test_manifests` |
| Authentication, vault rotation | `lab_verified` | `test_auth_hardening` (28). Browser login only where Chromium is installed |
| Validation chain, planner, graph trust, experience, reports, KB ingestion, agent contracts, skill pinning | `lab_verified` | the suites named in §3 |
| Subprocess worker backend | `lab_verified` on Windows (local) and Linux (CI, Python 3.12/3.13) | `test_worker_hardening` — and it is **not a sandbox** |
| Container backend lifecycle | `lab_verified` against a *fake* `docker` | proves our logic, not Docker's isolation |
| Container backend **isolation** | `lab_verified` on one real runtime (Docker 28.0.4, cgroup v2, GitHub-hosted Ubuntu 24.04) | `test_container_integration` (14 tests, CI); rootless and other runtimes untested |
| Egress allow-list firewall | `documented` | rendered ruleset, never applied |
| CI changes | `lab_verified` for `test`, `container-isolation`, the Linux `compatibility` jobs and the advisory audit; Windows matrix pending | first run on PR #42 |
| SQLi / XSS / SSRF testing in the pipeline | not implemented | see §5 |

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

**Docs/CI** — README roadmap heading with literal `\n`; README evaluator command failed without `--allow-missing`; stale register · D-CI-1 (found by the first Linux compatibility run) the real-browser auth test *errored* instead of skipping when the Playwright package was installed without a Chromium binary; a shared probe now launches a browser and skips, or fails when `WITHERHOARD_REQUIRE_BROWSER=1` (set by the CI `test` job so a broken Chromium install cannot pass by skipping) — `test_support` · D-CI-2 the advisory `pip-audit` job showed a red check on findings; it now publishes them to the job summary and annotates a warning.

## 5. Deliberately not implemented

After a safety stop during this work I did **not** build exploit-oriented probe or payload machinery: no SSRF callback/canary listener, no XSS breakout probe or context classifier, no intentionally vulnerable multi-class lab. SQLi/XSS/SSRF hypotheses are generated and recorded `INCONCLUSIVE` with a structured request for specialist testing, and counted as *not executed*. The pre-existing SQLi and reflected-XSS oracles judge evidence they are handed; the pre-existing `scripts/active_ssrf_probe.py` analyzer is operator-driven and not wired into the pipeline.

## 6. Remaining limitations and risks

* Container isolation is verified on one runtime only (Docker 28.0.4, cgroup v2, GitHub-hosted Ubuntu 24.04); rootless Docker, Podman and cgroup v1 hosts are untested, and a host that ignores cgroup limits would be caught by the same tests. The egress firewall template has never been applied to a host.
* The subprocess backend is not a sandbox. `RLIMIT_AS` can stop Go tools from starting; the process limit is relative to the user's current task count and approximate.
* `cryptography` is held to the 50.x line (`>=50.0.0,<51.0.0`): the floor clears four advisories reported by the audit (see §1), and the cap keeps the next major version out until CI has tested it. The audit is advisory and does not block merges.
* Only two authorization classes have automated executors; legacy validation records written before the evidence chain are never reported as vault-verified.
* Tool binaries are not version-probed. GitHub Actions are pinned by major tag, the test image by tag, dependencies by version — not by digest/commit.
* The control plane (scope, authorization, window, object ownership) is the operator's attestation. A manager and its SQLite connection belong to one thread.
* Two classes are named `ToolRegistry` (`core/workers/tools.py` worker allow-list, `core/tools/registry.py` layered over it) and `core/validation.py` (finding schema) sits beside `core/validation_engine/` (exploit validation): layered, not duplicated, but a naming hazard left unchanged.
* README/docs line endings are mixed (`core.autocrlf=true`); git normalises on commit.

## 7. To resume

1. Decide separately whether, and how, to automate SQLi/XSS/SSRF checks (needs an explicit design and authorization review).
2. Pin the container test image and the GitHub Actions by digest/commit (needs network access to look the values up and verify them).
3. Try the container isolation tests on rootless Docker or Podman, and apply the egress ruleset on a host.
4. Commit and open PRs only when asked (no AI attribution lines, per the project's convention).
