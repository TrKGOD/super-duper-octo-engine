# Isolated Execution Workers

Maturity (vocabulary in [`AUTONOMOUS_PLATFORM_ROADMAP.md`](AUTONOMOUS_PLATFORM_ROADMAP.md)):

| Part | Maturity | Basis |
|---|---|---|
| Worker manager: lifecycle, slots, ledger recording, crash reconciliation, per-engagement artifact isolation | `lab_verified` | `tests/test_worker_hardening.py`, `tests/test_isolated_workers.py` (Windows, Python 3.13) |
| Subprocess backend: wall clock, output flood kill, cancel, process-tree termination, scrubbed environment | `lab_verified` on Windows (local) and on Linux (CI, Python 3.12 and 3.13: the POSIX branches — `killpg`, `setrlimit`, the relative process limit — ran in the 730-test compatibility jobs) | tests above |
| Container backend lifecycle and command construction (preflight, naming, kill, rm, orphan sweep, fail-closed) | `lab_verified` against a *fake* `docker` executable | `ContainerBackendLifecycleTests` — proves **our** logic, not Docker's isolation |
| Container backend **isolation** (non-root, no capabilities, read-only root, read-only evidence mount, loopback-only network, cgroup limits, kill-and-remove, no implicit pull, digest pinning, orphan sweep) | `lab_verified` on **one real runtime**: Docker 28.0.4, cgroup v2, AppArmor + builtin seccomp, GitHub-hosted Ubuntu 24.04 | `tests/test_container_integration.py` (14 tests, all passed in the `container-isolation` CI job, which fails — never skips — if the runtime is missing). It cannot run on the development machine (no runtime). Rootless Docker, Podman and cgroup v1 hosts are untested |
| Egress allow-list firewall (`core/netpolicy.render_egress_firewall`) | `documented` | a rendered nftables template; never loaded into a real firewall |

This document is deliberately explicit about what is and is not a security boundary.

## What this provides

Separation of agent reasoning from tool execution. The `WorkerManager`
(`core/workers/manager.py`) provisions a worker per `(engagement, task)` with an
engagement-namespaced working directory, runs only **registered, allowlisted** tools with
**validated arguments**, **caps and sanitizes** their output, **bounds resources**,
**isolates artifacts per engagement**, records **observability** (`worker_executions`,
migration `012`) and every tool run as an execution in the unified **execution ledger**
(migration `014`, [`core/execution_ledger.py`](../core/execution_ledger.py)), and **cleans up**.

## Tool registry (`tools.py`)

Only registered tools run, and only with validated parameters substituted into fixed argv
slots — a parameter value becomes exactly one argv element and can never introduce new
arguments. A parameter may not start with `-` unless it explicitly opts in, control
characters and over-long values are rejected, and catalogue-style patterns cannot re-admit
option injection. Each tool declares id/name/version/purpose, parameter schema, required
permissions, network mode (`none` or `egress_allowlist`; anything else is refused when the
spec is defined), risk, timeout and output ceiling.

## Backends and the isolation boundary

### SubprocessWorkerBackend (portable, default) — **not a security sandbox**

Always enforces a **wall-clock timeout** and an **output ceiling**. A flood is *killed*, not
merely discarded. It runs with **no shell**, an **isolated working directory** and a
**scrubbed environment** (only OS-essential variables; no inherited secrets), and
terminates the **whole process tree**:

* POSIX — the tool starts in its own session; timeout, cancel and flood send `SIGKILL` to the group.
* Windows — the tool is assigned to a Job Object with kill-on-close; the job is terminated.

Cooperative cancellation (`CancelToken`) stops a running tool promptly. Resource limits:

* POSIX — `RLIMIT_CPU`, `RLIMIT_AS` (memory), `RLIMIT_NPROC`, `RLIMIT_FSIZE`.
* Windows — Job Object per-process memory and active-process limits.

Two caveats that matter when choosing tools to run under it:

* **Go binaries and `RLIMIT_AS`.** The Go runtime reserves address space; an address-space
  limit can stop a Go tool from starting at all. Run such tools in the container backend, where
  the limit is a cgroup memory limit.
* **`RLIMIT_NPROC` is per user, not per tool.** The kernel compares it with every task (process or
  thread) of the same user, so an absolute value below that count makes `fork()` and thread
  creation fail for the tool (`EAGAIN`) — on a busy workstation or CI runner a Go tool could not
  start. The backend therefore sets it to *the user's current task count + `max_processes`*,
  measured from `/proc` before the fork. Where `/proc` is unavailable the limit is **not applied**
  and the result says so (`limits_enforced.processes: false`). The bound is approximate: other
  activity of the same user during the run shares the headroom.

It is **not** a sandbox: it does not isolate the filesystem or network from the host and does
not constrain syscalls. It is appropriate only for tools that are already trusted and need
resource/time/output bounding — never for running untrusted tool code against a target. Its
`ExecutionResult` says so (`isolation="process"`, `network_enforced=False`), and
`WorkerManager.observability()` reports `sandboxed: false`.

### ContainerWorkerBackend (the isolation boundary)

`build_argv` constructs a hardened `docker run`: `--rm --init --pull never`, a unique
`--name` and `witherhoard.managed` labels, `--read-only` root, `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--ipc none`, `--pids-limit`, `--memory`/`--memory-swap`,
`--cpus`, `--ulimit nofile`, `--network none`, `noexec,nosuid,nodev` tmpfs for `/work` and
`/tmp`, a non-root `--user` (root is refused), and a **read-only** bind of the engagement
evidence directory. It refuses to emit `--privileged`, `--cap-add`, host namespaces, devices,
`seccomp=unconfined` or a docker-socket mount, and refuses a mount source containing
characters that could append `--mount` options.

Behaviour that is easy to get wrong, and is tested against the fake runtime:

* **Fails closed.** `preflight()` checks that the runtime exists and its daemon answers. If it
  does not, `run()` raises `ContainerRuntimeUnavailable`. There is no fallback to subprocess
  execution, and a manager built with `require_isolation=True` refuses a non-container backend.
* **Killing the client does not stop the container.** On timeout, cancel or output flood the
  backend runs `docker kill <name>` and always `docker rm -f <name>`; `cleanup_orphans()` sweeps
  by label after a crash.
* **The `docker` client is not held to the tool's resource limits.** The memory and process
  limits are requested from the runtime (`--memory`, `--pids-limit`) and enforced by its cgroup
  inside the container. Applying the same address-space or process-count limit to the local
  Go client crashes it, so the client is bounded by wall clock, output and cancellation only.
  The result therefore reports `limits_enforced` as false and lists what was *requested*; whether the
  host honoured the cgroup limits is what the integration test verifies.
* **No implicit pull.** `--pull never`; an operator may require a digest-pinned image
  (`require_pinned_image=True`) and `verify_image()` confirms the runtime holds that digest.
* **No default-bridge networking.** `network="egress_allowlist"` needs an operator-provisioned
  network (`egress_network`) and optional DNS servers; otherwise it raises.

## Threading

`StateStore`/SQLite connections belong to the thread that opened them, and so does a
`WorkerManager`. The only supported cross-thread control is `WorkerManager.request_cancel(worker_id)`,
which flips an in-memory token and touches no database state; the owning thread records the
outcome when the interrupted execution returns.

## Crash recovery

Every tool run is a ledger execution (`CREATED → QUEUED → AUTHORIZED → RUNNING → terminal`) with a
lease. After a crash, `WorkerManager.reconcile_interrupted()` classifies what was left behind and
**never re-runs anything**: worker rows still `provisioned`/`running` after `orphan_after_seconds`
(default one hour, and only if this process does not own them) are failed so they stop holding an
engagement slot; an execution that never dispatched becomes `INTERRUPTED`; one that had dispatched
becomes `RECONCILIATION_REQUIRED`, and only an operator's `resolve()` (with a reason) settles it;
labelled containers are swept. A timed-out tool is a classified failure in the ledger, not a success.

## Threat model and residual risks

**In scope (mitigated):**
- Argument and option injection into tool invocations — fixed-slot argv, leading-dash rule.
- Runaway time/output — wall clock, output ceiling and kill; POSIX/Windows resource limits.
- One engagement reading another's worker artifacts — per-engagement workdirs, component validation
  (`core/pathsafe.py`), and a link/junction-aware read guard.
- Unregistered or non-allowlisted tool execution — rejected before anything runs.
- Leftover processes and state — tree termination, workdir removal that does not follow links.
- Duplicate execution after a crash — never automatic.

**Residual risks (require the container backend plus host controls):**
- The subprocess backend lets a malicious tool read and write the host filesystem and open
  arbitrary network connections.
- Even the container backend is not perfect isolation: container escape, kernel vulnerabilities,
  side channels, rootless runtimes without cgroup delegation (limits silently not applied — the
  integration test exists to catch this) and the host's DNS/egress policy all remain the
  operator's responsibility.
- `render_egress_firewall()` produces a default-deny nftables ruleset; it has not been applied to
  a real host.
- In production the image is whatever the operator configures: a tag unless they require a digest
  (`require_pinned_image=True`). Only the CI test image is pinned by digest.

Do not describe the HTTP broker, the command guard, or the subprocess backend as a complete
sandbox. Untrusted tool execution must use the container backend with host-level egress and
filesystem controls.

## Running the isolation tests

```bash
docker pull busybox:1.36
WITHERHOARD_CONTAINER_TESTS=1 python -m unittest -v tests.test_container_integration tests.test_worker_hardening
```

Locally the default image is the `busybox:1.36` tag; CI sets `WITHERHOARD_CONTAINER_TEST_IMAGE` to the
image's digest (`busybox@sha256:…`, see `.github/workflows/ci.yml`), which `tests/test_ci_pins.py` requires.
With the gate unset those tests are skipped with an explicit reason; with it set, a missing
runtime or image is a **failure**. The orphan-sweep test removes every container labelled
`witherhoard.managed=true`, so it refuses to run on a runtime that already has such containers
unless `WITHERHOARD_CONTAINER_TESTS_DEDICATED_RUNTIME=1` declares the runtime disposable (CI does).

## Resource management and observability

Per-worker tool-invocation budget, per-engagement active-worker limit (provisioning is atomic),
per-tool timeout and output cap. Every worker records backend/image, task/engagement, timestamps,
status, each tool execution's metadata and resource figures, artifact names, and cleanup status.
A backend failure releases the engagement slot and is recorded rather than leaving a worker
`running`.

## Follow-ups

Run the container isolation tests on rootless Docker and Podman; apply and test the egress
ruleset on a host; register the real tool set (and load specs from configuration).
