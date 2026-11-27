"""Measured behaviour of the REAL pipeline against a local synthetic access-control fixture.

Four fixture policies give four ground truths (the fixture's own switches *are* the ground truth), so
the same run measures true positives AND false positives instead of assuming either. What is measured:

* precision / recall of confirmed findings against the ground truth;
* evidence completeness: every confirmed finding rests on a validation record whose evidence was
  resolved from the vault and still verifies by SHA-256;
* redundancy: requests repeated within a run, and requests sent when a further cycle has nothing new;
* coverage honesty: hypotheses with no automated executor are counted as not executed;
* cost: target requests, ledger executions and wall-clock time.

These are properties of a four-scenario synthetic fixture covering two authorization classes; its
discovered search form also produces sqli and xss hypotheses (both automated too, now), which this
fixture's ground truth does not track (true/false positive counts stay about idor_bola/bfla only) but
which still execute, get judged, and count toward coverage. All four show the pipeline agrees with
its ground truth there; they are NOT an estimate of detection quality on real applications, and SSRF
still has no automated executor reachable from this fixture (no URL-shaped parameter is discovered).

Run ``python -m tests.test_pipeline_metrics`` to print the measured table.
"""
import json
import time
import unittest

from core.evidence import EvidenceVault
from core.validation_engine import ValidationRecordStore
from tests.test_pipeline_e2e import AccessPolicyFixture, PipelineBase

RESULTS: list = []


class _MeasuredScenario:
    """Mixin: the scenario is the (enforce_ownership, protect_admin) pair of the PipelineBase subclass."""
    scenario = ""

    def measure(self) -> dict:
        pipeline = self.pipeline()
        pipeline.discover(self.origin + "/")
        self.seed_control_plane(declare_owner=True, bfla=True)
        discovery_hits = len(AccessPolicyFixture.hits)
        executions_before = len(self.http_executions())

        started = time.monotonic()
        report = pipeline.run()
        runtime = time.monotonic() - started
        testing_hits = AccessPolicyFixture.hits[discovery_hits:]
        executions_in_run = len(self.http_executions()) - executions_before

        before_repeat = len(AccessPolicyFixture.hits)
        repeat = pipeline.run()
        repeat_requests = len(AccessPolicyFixture.hits) - before_repeat

        truth = {"idor_bola": not self.enforce_ownership, "bfla": not self.protect_admin}
        statuses = {category: (self.hypothesis(category=category) or {"status": "MISSING"})["status"]
                    for category in truth}
        tp = sum(1 for c, vulnerable in truth.items() if vulnerable and statuses[c] == "SUPPORTED")
        fp = sum(1 for c, vulnerable in truth.items() if not vulnerable and statuses[c] == "SUPPORTED")
        fn = sum(1 for c, vulnerable in truth.items() if vulnerable and statuses[c] != "SUPPORTED")
        tn = sum(1 for c, vulnerable in truth.items() if not vulnerable and statuses[c] == "REFUTED")

        findings = self.connection.execute("SELECT * FROM findings WHERE status='validated'").fetchall()
        records = ValidationRecordStore(self.connection, self.lab.engagement_id)
        vault = EvidenceVault(self.lab.workflow.store, self.lab.root)
        complete = 0
        for category in truth:
            row = self.hypothesis(category=category)
            if row is None or row["status"] != "SUPPORTED":
                continue
            record = records.for_hypothesis(row["hypothesis_id"])[0]
            hashes = record["evidence_hashes"]
            if (record["evidence_verified"] and records.verify(record["record_id"]) and hashes
                    and all(vault.verify(item["evidence_id"])["valid"] for item in hashes)):
                complete += 1

        coverage = report["coverage"]["by_test_class"]
        hypotheses = sum(bucket["hypotheses"] for bucket in coverage.values())
        executed = sum(bucket["attempted"] for bucket in coverage.values())
        not_executed = sorted(row["category"] for row in self.connection.execute(
            "SELECT category FROM planner_hypotheses WHERE engagement_id=? AND executed=0",
            (self.lab.engagement_id,)))
        metrics = {
            "scenario": self.scenario, "ground_truth_vulnerable": truth, "hypothesis_status": statuses,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "validated_findings": len(findings),
            "findings_with_verified_evidence": complete,
            "hypotheses": hypotheses, "hypotheses_executed": executed,
            "hypotheses_without_automated_executor": hypotheses - executed,
            "categories_not_executed": not_executed,
            "target_requests_while_testing": len(testing_hits),
            "duplicate_requests_while_testing": len(testing_hits) - len(set(testing_hits)),
            "requests_in_a_cycle_with_nothing_new": repeat_requests,
            "ledger_executions_while_testing": executions_in_run,
            "cycles": report["cycles_run"], "runtime_seconds": round(runtime, 3),
            "repeat_stop_reason": repeat["stop_reason"],
        }
        RESULTS.append(metrics)
        return metrics

    def test_the_pipeline_agrees_with_the_ground_truth_and_wastes_nothing(self):
        metrics = self.measure()
        vulnerable = sum(metrics["ground_truth_vulnerable"].values())
        self.assertEqual((metrics["false_positives"], metrics["false_negatives"]), (0, 0), metrics)
        self.assertEqual(metrics["true_positives"], vulnerable, metrics)
        self.assertEqual(metrics["validated_findings"], vulnerable, "exactly one confirmed finding per real defect")
        self.assertEqual(metrics["findings_with_verified_evidence"], vulnerable, "every confirmation is vault-backed")
        self.assertEqual(metrics["duplicate_requests_while_testing"], 0, metrics)
        self.assertEqual(metrics["requests_in_a_cycle_with_nothing_new"], 0, metrics)
        self.assertEqual(metrics["repeat_stop_reason"], "no_ready_candidates")
        # sqli and xss (from the discovered search form) are automated too now: all 4 hypotheses
        # execute, none left uncovered. Judged honestly, not confirmed: the fixture's /search
        # route HTML-escapes "q", so xss correctly REFUTES, and sqli's boolean-pair probe gets the
        # same escaped payload reflected back in both samples -- the executor's own reflection-
        # confound check (core/pipeline/executor.py) declines to trust that differential rather
        # than let the pre-existing oracle read it as a false SQL-injection confirmation.
        self.assertEqual(metrics["hypotheses_without_automated_executor"], 0, metrics)
        self.assertEqual(metrics["hypotheses_executed"], 4, metrics)
        self.assertEqual(metrics["categories_not_executed"], [], metrics)
        sqli = self.hypothesis(category="sqli")
        self.assertEqual((sqli["status"], sqli["status_reason"]), ("INCONCLUSIVE", "reflection_confound"))
        xss = self.hypothesis(category="xss")
        self.assertEqual(xss["status"], "REFUTED")


class PermissiveFixtureMetrics(_MeasuredScenario, PipelineBase):
    scenario, enforce_ownership, protect_admin = "both_defects_present", False, False


class OwnershipEnforcedMetrics(_MeasuredScenario, PipelineBase):
    scenario, enforce_ownership, protect_admin = "only_function_level_defect", True, False


class AdminProtectedMetrics(_MeasuredScenario, PipelineBase):
    scenario, enforce_ownership, protect_admin = "only_object_level_defect", False, True


class FullyEnforcingMetrics(_MeasuredScenario, PipelineBase):
    scenario, enforce_ownership, protect_admin = "no_defect", True, True


def print_table() -> None:
    columns = ("scenario", "true_positives", "false_positives", "false_negatives", "true_negatives", "precision",
               "recall", "findings_with_verified_evidence", "hypotheses_executed", "hypotheses",
               "categories_not_executed", "target_requests_while_testing", "duplicate_requests_while_testing",
               "requests_in_a_cycle_with_nothing_new", "runtime_seconds")
    print(json.dumps({"measured_on": "local synthetic access-control fixture (4 policies, 2 authorization classes)",
                      "rows": [{column: row[column] for column in columns} for row in RESULTS]}, indent=2))


if __name__ == "__main__":
    unittest.main(exit=False)
    print_table()
