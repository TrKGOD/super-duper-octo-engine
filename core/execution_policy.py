"""Centralized active-execution throughput and concurrency safeguards.

There is no cumulative per-engagement request quota. Throughput and concurrency
remain bounded to prevent accidental traffic spikes.
"""
import math

MAX_REQUESTS_PER_SECOND = 5.0
MAX_CONCURRENCY = 1


def validate_execution_limits(rules):
    """Return validated (concurrency, requests_per_second)."""
    concurrency = rules.get("max_concurrency", 1)
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency != MAX_CONCURRENCY:
        raise ValueError("max_concurrency must be 1; concurrent broker execution is not implemented")
    rps = rules.get("requests_per_second", 1)
    if isinstance(rps, bool) or not isinstance(rps, (int, float)) or not 0 < rps <= MAX_REQUESTS_PER_SECOND or not math.isfinite(rps):
        raise ValueError(f"requests_per_second must be greater than 0 and at most {MAX_REQUESTS_PER_SECOND:g}")
    return concurrency, float(rps)
