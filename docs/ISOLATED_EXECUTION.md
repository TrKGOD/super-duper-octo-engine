# Isolated Execution Workers

**Phase 5 — foundation.** Status: `lab_verified` for the orchestration and the portable
backend; the container backend is **hardened by construction and tested at the command
level, but its runtime isolation is not exercised in CI** (no Docker). This document is
deliberately explicit about what is and is not a security boundary.

## What this provides

Separation of agent reasoning from tool execution. The `WorkerManager`
(`core/workers/manager.py`) provisions a worker per `(engagement, task)` with an
engagement-namespaced working directory, runs only **registered, allowlisted** tools with
**validated arguments**, **caps and sanitizes** their output, **bounds resources**,
**isolates artifacts per engagement**, records full **observability** (table
`worker_executions`, migration `012`), and **cleans up**.

## Tool registry (`tools.py`)

Only registered tools run, and only with validated parameters substituted into fixed argv
slots — a parameter value becomes exactly one argv element and can never introduce new
arguments, so there is no argument injection (`test_argument_validation_and_no_injection`).
Each tool declares id/name/version/purpose, parameter schema, required permissions, network
need, risk, timeout and output ceiling.

## Backends and the isolation boundary

### SubprocessWorkerBackend (portable, default) — **not a security sandbox**

Always enforces a **wall-clock timeout** and an **output ceiling** (bounded, draining
reader + pipe backpressure), runs with **no shell**, an **isolated working directory** and a
**scrubbed environment** (only OS-essential variables; no inherited secrets). On POSIX it
also applies `RLIMIT_CPU`, `RLIMIT_AS` (memory), `RLIMIT_NPROC` and `RLIMIT_FSIZE`, and runs
the tool in its own process group so a timeout kills the whole group.

It is **not** a sandbox: it does **not** isolate the filesystem or network from the host and
does not constrain syscalls. It is appropriate only for tools that are already trusted and
need resource/time/output bounding — never for running untrusted tool code against a target.

### ContainerWorkerBackend (the real isolation boundary)

`build_argv` constructs a hardened `docker run`: `--read-only` root, `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--pids-limit`, `--memory`/`--memory-swap`, `--cpus`,
`--network none` by default, a `noexec,nosuid` tmpfs workdir, an unprivileged `--user`, and
a read-only bind of the engagement evidence directory — and it refuses to ever emit
`--privileged`, `--cap-add` or a docker-socket mount (`test_command_is_hardened_by_construction`).
`run` delegates to an injected runner, so the hardened construction is tested without Docker.

## Threat model and residual risks

**In scope (mitigated):**
- Argument injection into tool invocations — prevented by fixed-slot argv substitution.
- Runaway CPU/time/output — bounded by timeout, output cap, and POSIX rlimits.
- One engagement reading another's worker artifacts — prevented by per-engagement workdirs
  and a path-escape guard on artifact reads (`test_cross_engagement_artifact_isolation`).
- Unregistered or non-allowlisted tool execution — rejected.
- Leftover state — workdir removed on teardown with a recorded cleanup status.

**Residual risks (NOT mitigated by the subprocess backend; require the container backend
plus host controls):**
- A malicious or compromised tool can read/write the host filesystem outside the workdir and
  make arbitrary network connections — the subprocess backend does not prevent this.
- Resource rlimits are POSIX-only; on Windows only the wall-clock and output bounds apply.
- Even the container backend is **not perfect isolation**: container escape, kernel
  vulnerabilities, side channels and DNS/egress policy enforcement all remain the host's
  responsibility. Network egress must be constrained by the host firewall; `--network none`
  is the safe default and any egress-allowlist mode depends on external network controls.
- The manager executes synchronously; mid-execution cancellation of an in-flight tool is
  best-effort (the timeout is the hard bound). True concurrent cancellation belongs to the
  container/async runner.

Do not describe the HTTP broker, the command guard, or the subprocess backend as a complete
sandbox. Untrusted tool execution must use the container backend with host-level egress and
filesystem controls.

## Resource management and observability

Per-worker tool-invocation budget, per-engagement active-worker limit, per-tool timeout and
output cap. Every worker records backend/image, task/engagement, timestamps, status, each
tool execution's metadata and resource figures, artifact names, and cleanup status.

## Tests

`tests/test_isolated_workers.py` (15): registry validation + no-injection + typed params;
subprocess backend run/timeout/output-cap; container command hardening + injected-runner
delegation; manager observability, unauthorized-tool rejection, cross-engagement artifact
isolation, invocation budget, cancellation, teardown cleanup, and per-engagement worker limit.

## Follow-ups

Provide a concrete container runner wired to a real runtime with CI that has Docker; add
DNS/egress-allowlist enforcement via the host; make execution cancellable mid-run; register
the real tool set (and load specs from configuration).
