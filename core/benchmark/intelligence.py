"""Intelligence-layer benchmarking (Component H).

Extends the Benchmark & Regression Lab with retrieval-quality, tool-selection-quality and
reporting-quality metrics for the Intelligence Layer (Components A / F / G). Like the existing
pipeline benchmark it is deterministic and CI-safe: every evaluator runs the **real** component
(the FTS retriever, the deterministic tool selector + profile policy, the reporting engine) on
synthetic, in-memory data — it contacts no live target and calls no model.

The real tool catalog (`core/tools/catalog.py`) is intentionally `requires_operator_configuration`
until an operator installs the binaries, so it would select nothing in CI. This benchmark
therefore measures the selector's *decision logic* on a controlled, available synthetic registry;
availability honesty is a separate, already-tested property. No decision code is mocked.

A regression gate compares two suite results and, independently of any baseline, **fails hard on
any safety violation** — a RESTRICTED tool auto-selected, or a scanner candidate / tampered-
evidence finding reaching a confirmed report section.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from scripts.migrate import migrate
from scripts.knowledge_base import connect, init_db
from core.store import StateStore, utc_now
from core.evidence import EvidenceVault
from core.validation_engine import FindingValidator
from core.knowledge import KnowledgeRetriever, ingest_content
from core.tools.observations import Observation, ObservationStore
from core.tools.profiles import ACTIVE_CONTROLLED, PASSIVE, ProfilePolicy, RESTRICTED, SAFE
from core.tools.registry import ToolDefinition, ToolRegistry
from core.tools.selection import CapabilityRequest, ToolSelector
from core.reporting import ReportingEngine
from core.workers.tools import ToolSpec
from core.benchmark.metrics import compute_metrics, retrieval_metrics, summarize_variance

RETRIEVAL_VERSION = "1.0"
SELECTION_VERSION = "1.0"
REPORTING_VERSION = "1.0"


def _mean(values):
    return summarize_variance([v for v in values if v is not None])["mean"]


# --------------------------------------------------------------------------- retrieval quality
_RETRIEVAL_META = {
    "platform": "Benchmark fixture", "disclosure_status": "public",
    "rights_basis": "Synthetic fixture authored for this benchmark.",
    "collected_at": "2026-11-26T00:00:00Z", "published_at": None,
    "content_type": "research_summary", "vulnerability_types": [], "technologies": [],
    "asset_types": ["api"], "tags": ["benchmark"], "author": None, "license": "CC0-1.0", "notes": None,
}

_CORPUS = {
    "bola": "Broken object level authorization is an IDOR where an object reference lets one "
            "tenant read another tenant's object without a server side ownership check.",
    "sqli": "SQL injection builds a database query from untrusted input and is exploited with "
            "union based and boolean blind techniques against the backend database.",
    "ssrf": "Server side request forgery makes the server fetch an attacker controlled URL, "
            "reaching cloud metadata and internal services behind the perimeter.",
    "xss": "Reflected cross site scripting echoes untrusted input into the HTML response where "
           "it executes as javascript in the victim browser.",
    "ssti": "Server side template injection evaluates untrusted input in a jinja template "
            "engine, leading to expression evaluation and remote code execution.",
}

_QUERIES = [
    {"query": "object level authorization idor tenant ownership", "relevant": {"bola"}},
    {"query": "sql database union based boolean blind", "relevant": {"sqli"}},
    {"query": "server side request forgery cloud metadata", "relevant": {"ssrf"}},
    {"query": "reflected cross site scripting javascript browser", "relevant": {"xss"}},
    {"query": "jinja template engine expression evaluation", "relevant": {"ssti"}},
    {"query": "injection", "relevant": {"sqli", "xss", "ssti"}},
]


def _seed_corpus(db) -> dict:
    ids = {}
    for topic, body in _CORPUS.items():
        meta = {**_RETRIEVAL_META, "title": topic.upper() + " writeup",
                "source_url": "https://example.org/kb/" + topic}
        ids[topic] = ingest_content(db, body, "text/plain", meta)
    return ids


def evaluate_retrieval(*, k: int = 5) -> dict:
    """Run the real FTS retriever over a synthetic corpus and score rank-aware quality."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db = connect(Path(tmp) / "kb.sqlite")
        try:
            init_db(db)
            ids = _seed_corpus(db)
            retriever = KnowledgeRetriever(db)
            rows = []
            for case in _QUERIES:
                relevant = {ids[topic] for topic in case["relevant"]}
                ranked = [r["document_id"] for r in retriever.retrieve_documents(case["query"], limit=k)]
                rows.append({"query": case["query"], **retrieval_metrics(relevant, ranked, k=k)})
            aggregate = {
                "mean_precision_at_k": _mean([r["precision_at_k"] for r in rows]),
                "mean_recall_at_k": _mean([r["recall_at_k"] for r in rows]),
                "mrr": _mean([r["reciprocal_rank"] for r in rows]),
                "map": _mean([r["average_precision"] for r in rows]),
                "mean_ndcg_at_k": _mean([r["ndcg_at_k"] for r in rows]),
                "query_count": len(rows),
            }
            return {"k": k, "corpus_size": len(ids), "queries": rows, "aggregate": aggregate}
        finally:
            db.close()


# ----------------------------------------------------------------------- tool-selection quality
_SELECTION_POLICY = {"execution_enabled": True, "authorization_verified": True,
                     "max_execution_profile": "active_controlled"}


def _bench_tool(tool_id, profile, capabilities, *, state_changing=False, vclasses=()) -> ToolDefinition:
    spec = ToolSpec(tool_id, tool_id, "1.0", "benchmark synthetic tool", command=(tool_id,))
    return ToolDefinition(tool_id=tool_id, name=tool_id, category="benchmark", version="1.0",
                          spec=spec, capabilities=tuple(capabilities),
                          vulnerability_classes=tuple(vclasses), execution_profile=profile,
                          state_changing=state_changing, binary=None, status="integrated")


def _selection_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for definition in (
        _bench_tool("passive-osint", PASSIVE, ("subdomain_discovery",)),
        _bench_tool("safe-http", SAFE, ("http_probing",)),
        _bench_tool("safe-http-alt", SAFE, ("http_probing",)),          # redundant with safe-http
        _bench_tool("active-fuzz", ACTIVE_CONTROLLED, ("content_discovery",)),
        _bench_tool("active-writer", ACTIVE_CONTROLLED, ("content_discovery",), state_changing=True),
        _bench_tool("restricted-exploit", RESTRICTED, ("exploitation",), vclasses=("rce",)),
    ):
        registry.register(definition)
    return registry


def _selection_cases() -> list[dict]:
    return [
        {"name": "passive_discovery", "expected": {"passive-osint"}, "forbidden": set(),
         "request": CapabilityRequest(capability="subdomain_discovery")},
        {"name": "safe_probing_selects_both", "expected": {"safe-http", "safe-http-alt"},
         "forbidden": set(), "request": CapabilityRequest(capability="http_probing")},
        {"name": "redundancy_defers_covered", "expected": set(), "forbidden": set(),
         "request": CapabilityRequest(capability="http_probing", covered_capabilities=("http_probing",))},
        {"name": "state_change_needs_approval", "expected": {"active-fuzz"},
         "forbidden": {"active-writer"}, "request": CapabilityRequest(capability="content_discovery")},
        {"name": "restricted_never_auto", "expected": set(), "forbidden": {"restricted-exploit"},
         "request": CapabilityRequest(capability="exploitation")},
        {"name": "restricted_with_operator_approval", "expected": {"restricted-exploit"},
         "forbidden": set(),
         "request": CapabilityRequest(capability="exploitation", auto_selected=False,
                                      operator_approved=True)},
    ]


def evaluate_tool_selection() -> dict:
    """Run the real deterministic selector + profile policy over a controlled, available set."""
    registry = _selection_registry()
    selector = ToolSelector(registry, policy=ProfilePolicy(_SELECTION_POLICY))

    rows, f1s, correctness, violations = [], [], [], 0
    for case in _selection_cases():
        result = selector.select(case["request"])
        selected = {tool["tool_id"] for tool in result["selected"]}
        metrics = compute_metrics({(t,) for t in case["expected"]}, {(t,) for t in selected})
        exact = selected == case["expected"]
        # Safety: a forbidden tool selected, or ANY restricted tool auto-selected.
        leaked = selected & case["forbidden"]
        restricted_auto = {tid for tid in selected
                           if registry.get(tid).execution_profile == RESTRICTED
                           and case["request"].auto_selected and not case["request"].operator_approved}
        case_violations = sorted(leaked | restricted_auto)
        violations += len(case_violations)
        correctness.append(1.0 if exact else 0.0)
        if metrics["f1"] is not None:
            f1s.append(metrics["f1"])
        rows.append({"name": case["name"], "selected": sorted(selected),
                     "expected": sorted(case["expected"]), "exact_match": exact,
                     "precision": metrics["precision"], "recall": metrics["recall"],
                     "f1": metrics["f1"], "safety_violations": case_violations})
    aggregate = {
        "case_count": len(rows), "accuracy": _mean(correctness), "mean_f1": _mean(f1s),
        "safety_violations": violations, "all_correct": all(r["exact_match"] for r in rows),
    }
    return {"cases": rows, "aggregate": aggregate}


# -------------------------------------------------------------------------- reporting quality
def _bola_request():
    owner = {"status_code": 200, "response_excerpt": '{"id":1}', "evidence_refs": ["o1"]}
    other = {"status_code": 200, "response_excerpt": '{"id":1}', "evidence_refs": ["o2"]}
    return {"vulnerability_class": "object_authorization", "owner_response": owner,
            "other_response": other, "owner_identity": "bob", "other_identity": "alice",
            "object_reference": "order-7"}


def _validated_finding(store, vault, validator, engagement_id, fid, title) -> dict:
    # Distinct content per finding: the vault is content-addressed, so identical bytes would
    # dedupe to one blob and tampering one finding's evidence would corrupt the other's.
    ev = vault.capture(engagement_id, "http_exchange", fid + "-ev.txt",
                       b"GET /api/orders/7 synthetic " + fid.encode(), "recon-agent", redacted=True)
    store.record_finding({
        "finding_id": fid, "engagement_id": engagement_id, "title": title,
        "status": "validation_pending", "asset": "https://app.local/api/orders", "method": "GET",
        "parameter": "id", "description": "Cross-identity object access.",
        "impact": "Tenant data exposure.", "severity": "high", "proposed_by": "recon-agent",
        "evidence_refs": [ev["evidence_id"]]})
    validator.validate_finding(fid, _bola_request(), "validation-agent")
    return ev


def evaluate_reporting() -> dict:
    """Run the real reporting engine over an engagement with one sound confirmed finding, one
    tampered-evidence finding (must be excluded), and a scanner candidate (must stay separate)."""
    engagement_id = "bench-report"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        db = str(root / "state.sqlite3")
        migrate(db)
        store = StateStore(db)
        try:
            store.create_engagement(engagement_id, "AUTH", {"allowed_domains": ["app.local"]}, {},
                                    status="active")
            vault = EvidenceVault(store, root)
            validator = FindingValidator(store)
            _validated_finding(store, vault, validator, engagement_id, "rep-good", "IDOR sound")
            tampered = _validated_finding(store, vault, validator, engagement_id, "rep-bad", "IDOR tampered")
            (root / tampered["local_path"]).write_bytes(b"tampered-after-validation")
            ObservationStore(store.connection, engagement_id).add(Observation(
                engagement_id=engagement_id, tool_id="nuclei", observation_type="vulnerability_candidate",
                disposition="CANDIDATE", vulnerability_class="cve", severity_candidate="medium",
                target_reference="https://app.local/x"))

            engine = ReportingEngine(store, root)
            report = engine.build("technical", engagement_id)
            confirmed = {f["finding_id"] for f in report["confirmed_findings"]}
            excluded = {f["finding_id"] for f in report["excluded_findings"]}
            candidates = report["unvalidated"]["candidate_observations"]
            sarif = json.loads(engine.render(report, "sarif"))
            sarif_results = len(sarif["runs"][0]["results"])

            confirmed_correct = 1.0 if confirmed == {"rep-good"} else 0.0
            tampered_excluded = 1.0 if "rep-bad" in excluded and "rep-bad" not in confirmed else 0.0
            candidate_separated = 1.0 if len(candidates) == 1 else 0.0
            sarif_confirmed_only = 1.0 if sarif_results == len(confirmed) else 0.0
            # Anything confirmed other than the one sound finding is an integrity leak.
            integrity_violations = len(confirmed - {"rep-good"})

            checks = {"confirmed_correct": confirmed_correct, "tampered_excluded": tampered_excluded,
                      "candidate_separated": candidate_separated,
                      "sarif_confirmed_only": sarif_confirmed_only}
            aggregate = {"score": round(sum(checks.values()) / len(checks), 6),
                         "integrity_violations": integrity_violations,
                         "all_pass": integrity_violations == 0 and all(v == 1.0 for v in checks.values())}
            return {"checks": checks, "confirmed": sorted(confirmed), "excluded": sorted(excluded),
                    "candidate_count": len(candidates), "aggregate": aggregate}
        finally:
            store.close()


# ------------------------------------------------------------------------------- suite + gate
def _manifest() -> dict:
    return {"retrieval_version": RETRIEVAL_VERSION, "selection_version": SELECTION_VERSION,
            "reporting_version": REPORTING_VERSION, "generated_at": utc_now(),
            "no_live_targets": True, "no_model_calls": True}


def run_intelligence_suite() -> dict:
    retrieval = evaluate_retrieval()
    selection = evaluate_tool_selection()
    reporting = evaluate_reporting()
    safety_violations = (selection["aggregate"]["safety_violations"]
                         + reporting["aggregate"]["integrity_violations"])
    aggregate = {
        "retrieval_map": retrieval["aggregate"]["map"],
        "retrieval_mrr": retrieval["aggregate"]["mrr"],
        "selection_accuracy": selection["aggregate"]["accuracy"],
        "reporting_score": reporting["aggregate"]["score"],
        "safety_violations": safety_violations,
        "all_safe": safety_violations == 0,
    }
    return {"retrieval": retrieval, "tool_selection": selection, "reporting": reporting,
            "aggregate": aggregate, "manifest": _manifest(),
            "cost": {"usd": 0.0, "note": "synthetic deterministic run; no model or network cost"}}


_HIGHER_IS_BETTER = ("retrieval_map", "retrieval_mrr", "selection_accuracy", "reporting_score")


def compare_intelligence(baseline: dict, candidate: dict) -> dict:
    """Regression comparison of two intelligence-suite results. A drop in any headline metric is
    a regression, and any safety violation in the candidate is a hard failure regardless of the
    baseline."""
    base, cand = baseline.get("aggregate", {}), candidate.get("aggregate", {})
    deltas, regressed = {}, []
    for key in _HIGHER_IS_BETTER:
        bv, cv = base.get(key), cand.get(key)
        if isinstance(bv, (int, float)) and isinstance(cv, (int, float)):
            deltas[key] = round(cv - bv, 6)
            if cv < bv - 1e-9:
                regressed.append(key)
    safety_violations = cand.get("safety_violations", 0)
    return {"deltas": deltas, "regressed": regressed, "safety_violations": safety_violations,
            "safety_failed": bool(safety_violations),
            "is_regression": bool(regressed) or bool(safety_violations)}
