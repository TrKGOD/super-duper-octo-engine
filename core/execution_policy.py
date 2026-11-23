"""Centralized, configurable active-execution limits with hard safety ceilings."""

import math


MAX_REQUESTS_PER_SECOND = 5.0
MAX_REQUESTS_PER_ENGAGEMENT = 500
MAX_CONCURRENCY = 1


def validate_execution_limits(rules):
    """Return validated (concurrency, requests_per_second, request_budget).

    Engagements may tune throughput and total request volume within explicit
    hard ceilings. Concurrency remains one until the broker has a tested
    multi-worker lease and budget-reservation implementation.
    """
    concurrency = rules.get("max_concurrency", 1)
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency != MAX_CONCURRENCY:
        raise ValueError("max_concurrency must be 1; concurrent broker execution is not implemented")

    rps = rules.get("requests_per_second", 1)
    if isinstance(rps, bool) or not isinstance(rps, (int, float)) or not math.isfinite(rps) or not 0 < rps <= MAX_REQUESTS_PER_SECOND:
        raise ValueError(f"requests_per_second must be greater than 0 and at most {MAX_REQUESTS_PER_SECOND:g}")

    budget = rules.get("max_requests_per_engagement", 20)
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= MAX_REQUESTS_PER_ENGAGEMENT:
        raise ValueError(f"max_requests_per_engagement must be between 1 and {MAX_REQUESTS_PER_ENGAGEMENT}")

    return concurrency, float(rps), budget
