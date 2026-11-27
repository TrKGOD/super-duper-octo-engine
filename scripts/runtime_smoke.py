#!/usr/bin/env python3
"""Run a bounded, no-tool Claude Code smoke test for one repository agent."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # allow `python scripts/<name>.py` to import core.*
from core.runtime import CHILD_TEXT_ENCODING, resolve_executable


def parse_agent_result(stdout):
    """Parse Claude CLI JSON output, accepting fenced JSON in its result field."""
    envelope = json.loads(stdout)
    if not isinstance(envelope, dict):
        raise ValueError("Claude Code returned an invalid JSON envelope")
    result_text = envelope.get("result", "")
    if isinstance(result_text, dict):
        result = result_text
    elif isinstance(result_text, str):
        text = result_text.strip()
        text = re.sub(r"^\s*[`]{3}(?:json)?\s*|\s*[`]{3}\s*$", "", text, flags=re.I)
        result = json.loads(text)
    else:
        raise ValueError("Claude Code result field is not JSON text or an object")
    return envelope, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="vulnerability-agent")
    parser.add_argument("--model", required=True)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()
    if args.timeout_seconds < 10:
        parser.error("--timeout-seconds must be at least 10")
    binary = resolve_executable(args.claude_bin)
    if not binary:
        print("Claude Code CLI not found", file=sys.stderr)
        return 2

    prompt = (
        "Runtime smoke test for agent: " + args.agent + ".\n"
        "AGENT NAME: " + args.agent + "\n"
        "This is synthetic data only; do not use tools or network. "
        "Return JSON with keys smoke_test, agent, status, summary. "
        "Set smoke_test to true, agent to the requested agent name, status to "
        "\"completed\" only if you can follow this instruction, and summary to a "
        "short description. Do not claim any target was tested."
    )
    command = [
        binary, "-p", "--agent", args.agent, "--model", args.model,
        "--output-format", "json", "--max-turns", "1", "--tools", "",
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, input=prompt, capture_output=True, text=True, **CHILD_TEXT_ENCODING,
            timeout=args.timeout_seconds, check=False,
            env=dict(os.environ, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"),
        )
    except subprocess.TimeoutExpired:
        print("Runtime smoke test timed out", file=sys.stderr)
        return 2
    elapsed = round(time.monotonic() - started, 3)
    if proc.returncode:
        print("Claude Code failed: " + proc.stderr[-2000:], file=sys.stderr)
        return 2
    try:
        envelope, result = parse_agent_result(proc.stdout)
    except (json.JSONDecodeError, AttributeError, TypeError):
        print("Claude Code did not return a parseable JSON result", file=sys.stderr)
        return 2
    if not isinstance(result, dict) or result.get("smoke_test") is not True:
        print("Agent response did not satisfy the smoke-test contract", file=sys.stderr)
        return 2
    if result.get("agent") != args.agent or result.get("status") != "completed":
        print("Agent identity/status mismatch in smoke-test response", file=sys.stderr)
        return 2

    usage = {
        key: envelope[key]
        for key in ("total_cost_usd", "usage", "modelUsage", "duration_ms",
                    "duration_api_ms", "num_turns", "stop_reason")
        if key in envelope
    }
    print(json.dumps({
        "status": "completed",
        "agent": args.agent,
        "model": args.model,
        "elapsed_seconds": elapsed,
        "usage_available": bool(usage),
        "usage": usage,
        "summary": result.get("summary", ""),
        "limitations": [
            "Single-agent runtime smoke only; not an orchestrator-to-specialist handoff test.",
            "No tools or network access were enabled.",
            "Does not prove Skills were dynamically selected or loaded.",
        ],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
