"""Deterministic execution of a planner hypothesis, end to end.

``PipelineExecutor`` is the planner's executor. The planner proposes and prioritises; this class
is the layer that actually *does* the work, and it adds no authority of its own:

    hypothesis
      -> tool selection      registry + execution-profile policy (RESTRICTED is never auto-selected)
      -> plan                inputs come from control-plane graph facts, never from the proposer
      -> task + pinned manifests, created through Workflow.create_plan (scope re-checked there)
      -> execution           ONLY through the scope-enforcing HTTP broker (DNS pinning, rate limit,
                             request pinning, ledger entry, evidence capture with execution link)
      -> validation          ExploitValidationEngine on evidence it resolves and hashes itself
      -> finding lifecycle   an independent validator run; proposer != validator
      -> graph               observed access, finding node, validation edges

Nothing here opens a socket or starts a process. Every failure is returned as an explicit
INCONCLUSIVE result carrying a structured *evidence request* telling the operator (or the next
planning cycle) what is missing — it is never converted into a confirmation or hidden.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from core.active_executor import (ActiveExecutionError, ActiveHTTPExecutor, _application_match,
                                  _host_matches, _ip_in_scope)
from core.authorization_execution import execute_object_access_comparison
from core.errors import classify_exception
from core.graph.ingest import GraphIngestor, IngestError
from core.orchestration import WorkflowError, _scope_assets
from core.pathsafe import is_link_like
from core.pipeline.identities import IdentityDirectory
from core.pipeline.strategies import STRATEGIES
from core.pipeline.tools import build_pipeline_registry
from core.planner.hypothesis import HypothesisStore
from core.redaction import redact
from core.security_testing import execute_readonly_pair
from core.store import new_id
from core.tools.profiles import ProfilePolicy
from core.tools.selection import CapabilityRequest, ToolSelector
from core.validation_engine import (EvidenceResolver, ExploitValidationEngine, FindingValidator,
                                    GraphFacts, SUPPORTED, ValidationError, ValidationRecordStore)
from core.validation_engine.oracles import evidence_request

_READ_METHODS = ("GET", "HEAD")


class PipelineExecutor:
    AGENT = "active-testing-agent"
    PROPOSER = "adaptive-planner"
    VALIDATOR = "exploit-validation-engine"

    def __init__(self, workflow, engagement_id: str, graph, identities: IdentityDirectory, *,
                 registry=None, project_root=None, audit=None):
        self.workflow = workflow
        self.engagement_id = engagement_id
        self.graph = graph
        self.identities = identities
        self.store = workflow.store
        self.project_root = Path(project_root) if project_root is not None else workflow.project_root
        self.audit = audit or (lambda event, details: None)
        self.http = ActiveHTTPExecutor(workflow, self.project_root)
        self.vault = self.http.vault
        self.registry = registry or build_pipeline_registry()
        self.registry.declare("http_broker", True)        # we hold a broker for this engagement
        row = self.store.connection.execute(
            "SELECT scope_json,rules_json FROM engagements WHERE engagement_id=?", (engagement_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown engagement: " + str(engagement_id))
        self.scope = json.loads(row["scope_json"])
        self.selector = ToolSelector(self.registry, ProfilePolicy(json.loads(row["rules_json"])))
        self.facts = GraphFacts(graph)
        self.ingestor = GraphIngestor(graph)
        self.engine = ExploitValidationEngine(
            engagement_id, record_store=ValidationRecordStore(self.store.connection, engagement_id),
            resolver=EvidenceResolver(self.vault, engagement_id), facts=self.facts)
        self.finding_validator = FindingValidator(self.store, self.vault, validator_id=self.VALIDATOR)

    # ---------------------------------------------------------------------------------------
    def __call__(self, hypothesis: dict) -> dict:
        strategy = STRATEGIES.get(hypothesis["category"])
        if strategy is None or not strategy.automated:
            note = strategy.note if strategy else "unknown hypothesis category"
            return self._inconclusive("no_automated_executor:" + str(hypothesis["category"]), [
                evidence_request("specialist_testing_required", note, category=hypothesis["category"])])
        selection = self.selector.select(CapabilityRequest(
            capability=strategy.capability, max_profile=strategy.max_profile, auto_selected=True))
        if not selection["selected"]:
            return self._inconclusive("no_authorized_tool", [evidence_request(
                "tool_unavailable", "no available, authorized tool provides " + strategy.capability,
                rejected=selection["rejected"], deferred=selection["deferred"])])
        tool = selection["selected"][0]
        plan = getattr(self, "_plan_" + strategy.category)(hypothesis)
        if "needs" in plan:
            return self._inconclusive(plan["reason"], plan["needs"])
        return self._execute_pair(hypothesis, strategy, tool, plan)

    # -- results -----------------------------------------------------------------------------
    @staticmethod
    def _inconclusive(reason: str, requests: list, **extra) -> dict:
        # ``executed`` is False unless the caller says a request really reached the target.
        return {"disposition": "INCONCLUSIVE", "reason": reason, "evidence_refs": [], "executed": False,
                "evidence_requests": requests, **extra}

    # -- planning: inputs from control-plane facts -------------------------------------------------
    def _endpoint(self, hypothesis):
        node = self.graph.get_node_by_id(hypothesis["target_node_id"]) if hypothesis.get("target_node_id") else None
        if node is None or node["node_type"] not in ("endpoint", "route"):
            return None
        attrs = node["attributes"]
        if not attrs.get("origin") or not attrs.get("path"):
            return None
        return node

    def _needs_credentials(self, *identities):
        missing = [i for i in identities if self.identities.secret_headers(i) is None]
        if missing:
            return {"reason": "identity_credentials_not_provisioned", "needs": [evidence_request(
                "provision_identity_credentials", "no credential reference is registered for the identity",
                identities=missing)]}
        return None

    def _plan_idor_bola(self, hypothesis) -> dict:
        node = self._endpoint(hypothesis)
        actor = hypothesis.get("required_identity")
        if node is None or not actor:
            return {"reason": "target_or_identity_missing", "needs": [evidence_request(
                "select_actor_identity", "an in-scope endpoint and an authorized identity are required")]}
        attrs = node["attributes"]
        method = str(attrs.get("method", "GET")).upper()
        if method not in _READ_METHODS:
            return {"reason": "not_a_read_only_endpoint", "needs": [evidence_request(
                "operator_pinned_manifests", "only read-only comparisons run automatically", method=method)]}
        references = self.graph.edges("REFERENCES", src_id=node["node_id"]) + self.graph.edges("RETURNS", src_id=node["node_id"])
        candidates, undeclared = [], False
        for edge in references:
            obj = self.graph.get_node_by_id(edge["dst"])
            if obj is None or obj["node_type"] != "object":
                continue
            owner = self.facts.object_owner(obj["key"])     # control-plane declaration or nothing
            if owner is None:
                undeclared = True
            elif owner != actor:
                candidates.append((obj, owner))
        if not candidates:
            return {"reason": "object_ownership_not_declared" if (undeclared or not references)
                    else "no_cross_identity_object",
                    "needs": [evidence_request("confirm_object_ownership",
                                               "no object with an operator-declared owner other than the actor is referenced",
                                               endpoint=node["key"], actor=actor)]}
        obj, owner = sorted(candidates, key=lambda item: item[0]["key"])[0]
        missing = self._needs_credentials(actor, owner)
        if missing:
            return missing
        if not self.identities.distinct(owner, actor):
            return {"reason": "identities_share_credentials", "needs": [evidence_request(
                "distinct_identity_credentials", "the two identities must use different credential references")]}
        path = attrs["path"]
        if "{id}" in path:
            identifier = obj["attributes"].get("identifier")
            if identifier is None:
                return {"reason": "object_identifier_not_declared", "needs": [evidence_request(
                    "declare_object_identifier", "the path template needs a concrete identifier for the object",
                    object=obj["key"])]}
            path = path.replace("{id}", quote(str(identifier), safe=""))
        return {"url": attrs["origin"].rstrip("/") + path, "method": method, "endpoint": node,
                "first_identity": owner, "second_identity": actor, "object_reference": obj["key"]}

    def _plan_bfla(self, hypothesis) -> dict:
        node = self._endpoint(hypothesis)
        actor = hypothesis.get("required_identity")
        if node is None or not actor:
            return {"reason": "target_or_identity_missing", "needs": [evidence_request(
                "select_actor_identity", "an in-scope endpoint and an authorized identity are required")]}
        attrs = node["attributes"]
        method = str(attrs.get("method", "GET")).upper()
        if method not in _READ_METHODS:
            return {"reason": "not_a_read_only_endpoint", "needs": [evidence_request(
                "operator_pinned_manifests", "only read-only comparisons run automatically", method=method)]}

        def role_names(identity_key, edge_filter):
            ident = self.graph.get_node("identity", identity_key) or self.graph.get_node("user", identity_key)
            if ident is None:
                return []
            names = []
            for edge in self.graph.edges("HAS_ROLE", src_id=ident["node_id"]):
                role = self.graph.get_node_by_id(edge["dst"])
                if role and edge["trust"] == "control_plane":
                    names.append(role["key"])
            return sorted(names)

        granted = sorted({self.graph.get_node_by_id(e["src"])["key"]
                          for e in self.graph.edges("CAN_ACCESS", dst_id=node["node_id"])
                          if e["trust"] == "control_plane" and self.graph.get_node_by_id(e["src"])
                          and self.graph.get_node_by_id(e["src"])["node_type"] == "role"})
        actor_roles = role_names(actor, None)
        restricted = [role for role in granted if role not in actor_roles]
        if not restricted:
            return {"reason": "function_restriction_not_declared", "needs": [evidence_request(
                "confirm_function_role_restriction", "the control plane does not restrict this function to a role "
                "the actor lacks", function=node["key"], actor=actor)]}
        baseline_role = restricted[0]
        baseline = next((i["key"] for i in self.graph.nodes("identity") + self.graph.nodes("user")
                         if baseline_role in role_names(i["key"], None) and self.identities.secret_headers(i["key"])), None)
        if baseline is None:
            return {"reason": "no_baseline_identity", "needs": [evidence_request(
                "provision_identity_credentials", "no identity holding the restricted role has credentials",
                role=baseline_role)]}
        missing = self._needs_credentials(actor, baseline)
        if missing:
            return missing
        if not self.identities.distinct(baseline, actor):
            return {"reason": "identities_share_credentials", "needs": [evidence_request(
                "distinct_identity_credentials", "the two identities must use different credential references")]}
        return {"url": attrs["origin"].rstrip("/") + attrs["path"], "method": method, "endpoint": node,
                "first_identity": baseline, "second_identity": actor, "function_reference": node["key"],
                "baseline_role": baseline_role, "comparison_role": (actor_roles or ["unprivileged"])[0]}

    # -- execution ---------------------------------------------------------------------------------
    def _scope_subset(self, url: str) -> list:
        host = (urlsplit(url).hostname or "").lower()
        for asset in sorted(_scope_assets(self.scope)):
            if "://" in asset:
                if _application_match(url, [asset]):
                    return [asset]
            elif _host_matches(host, asset) or asset == host:
                return [asset]
            else:
                try:
                    if _ip_in_scope(host, {"allowed_ips": [asset], "allowed_cidrs": [asset]}):
                        return [asset]
                except ValueError:
                    continue
        return []

    def _pin(self, request: dict) -> dict:
        root = self.project_root
        directory = root / ".local" / "requests"
        directory.mkdir(parents=True, exist_ok=True)
        if is_link_like(root / ".local") or is_link_like(directory):
            raise ActiveExecutionError(".local/requests must not be a symlink or junction")
        raw = json.dumps(request, sort_keys=True).encode()
        name = request["request_id"] + ".json"
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # never overwrite
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return {"path": ".local/requests/" + name, "sha256": hashlib.sha256(raw).hexdigest()}

    def _manifest(self, request_id: str, plan: dict, identity: str, hypothesis_id: str) -> dict:
        return {"request_id": request_id, "method": plan["method"], "url": plan["url"],
                "purpose": f"Authorized read-only authorization comparison for hypothesis {hypothesis_id[4:16]} "
                           "(deterministic pipeline)",
                "secret_headers": self.identities.secret_headers(identity), "timeout_seconds": 8,
                "max_response_bytes": 65536, "follow_redirects": False}

    def _close_task(self, task_id: str, scope_subset: list, *, ok: bool, evidence_refs: list, summary: str):
        handoff = {"task_id": task_id, "engagement_id": self.engagement_id, "agent": self.AGENT,
                   "status": "completed" if ok else "blocked", "scope_subset": scope_subset,
                   "summary": summary, "observations": [], "hypotheses": [],
                   "evidence_refs": list(dict.fromkeys(evidence_refs)),
                   "limitations": ["Executed by the deterministic pipeline through the scope-enforcing broker; "
                                   "no language model took part in this task."]}
        try:
            self.workflow.accept_handoff(task_id, handoff)
        except WorkflowError as exc:
            # Never leave the task row 'running': record why the handoff was refused and fail it.
            self.audit("pipeline.handoff_rejected", {"task_id": task_id, "reason": redact(str(exc))[:200]})
            self.store.update_task(task_id, "failed", {"handoff_error": redact(str(exc))[:200]})

    def _execute_pair(self, hypothesis, strategy, tool, plan) -> dict:
        hid = hypothesis["hypothesis_id"]
        subset = self._scope_subset(plan["url"])
        if not subset:
            return self._inconclusive("target_outside_engagement_assets", [evidence_request(
                "scope_review", "the target is not covered by an explicit engagement asset")])
        nonce = uuid.uuid4().hex[:10]
        first = self._manifest(f"pl-{nonce}-a", plan, plan["first_identity"], hid)
        second = self._manifest(f"pl-{nonce}-b", plan, plan["second_identity"], hid)
        try:
            pinned = [self._pin(first), self._pin(second)]
            created = self.workflow.create_plan(self.engagement_id, {"tasks": [{
                "task_key": f"pipeline-{hid[4:16]}-{nonce}", "agent": self.AGENT,
                "objective": f"Compare access to {plan['url']} between two approved identities",
                "completion_criteria": ["Both requests executed through the broker with evidence"],
                "scope_subset": subset, "domain": "web", "skill_tags": ["http-read-only"],
                "active_testing": True, "request_files": pinned}]})
            task_id = created[0]["task_id"]
            self.workflow.start_task(task_id, model="deterministic-pipeline")
            # Link the hypothesis to its task *before* anything is sent: if this process dies mid-way,
            # recovery can still find the executions that may already have reached the target.
            HypothesisStore(self.store.connection, self.engagement_id).set_last_execution(hid, "task:" + task_id)
        except (WorkflowError, ActiveExecutionError, OSError) as exc:
            return self._inconclusive("plan_refused", [evidence_request(
                "plan_refused", redact(str(exc))[:200], failure_class=classify_exception(exc))])

        try:
            if strategy.category == "idor_bola":
                outcome = execute_object_access_comparison(
                    self.http, self.engagement_id, task_id, pinned[0]["path"], pinned[1]["path"],
                    owner_identity=plan["first_identity"], other_identity=plan["second_identity"],
                    object_reference=plan["object_reference"])
                first_result, second_result = outcome.get("owner_response"), outcome.get("other_response")
            else:
                outcome = execute_readonly_pair(
                    self.http, self.engagement_id, task_id, pinned[0]["path"], pinned[1]["path"],
                    identity_mode="two_identities", first_label=plan["first_identity"],
                    second_label=plan["second_identity"])
                first_result, second_result = outcome.get("first_response"), outcome.get("second_response")
        except ActiveExecutionError as exc:
            self._close_task(task_id, subset, ok=False, evidence_refs=[], summary="Execution was refused: " + redact(str(exc))[:160])
            return self._inconclusive("execution_refused", [evidence_request(
                "execution_refused", redact(str(exc))[:200], failure_class=classify_exception(exc))], task_id=task_id)

        all_refs = [ref for result in (first_result, second_result) if result for ref in result.get("evidence_refs", [])]
        if outcome.get("status") != "comparison_completed" or not first_result or not second_result:
            self._close_task(task_id, subset, ok=False, evidence_refs=all_refs,
                             summary="Only part of the comparison completed.")
            return self._inconclusive("partial_execution", [evidence_request(
                "reconcile_partial_execution", "one request of the pair did not complete; the execution ledger "
                "shows its state and an operator must decide whether to re-plan", task_id=task_id)],
                evidence_refs=all_refs, execution_id=(first_result or {}).get("execution_id"), task_id=task_id,
                executed=True)

        first_response_ev, second_response_ev = first_result["evidence_refs"][1], second_result["evidence_refs"][1]
        if strategy.category == "idor_bola":
            request = {"vulnerability_class": strategy.vulnerability_class, "hypothesis_id": hid,
                       "evidence": {"owner_response": first_response_ev, "other_response": second_response_ev},
                       "owner_identity": plan["first_identity"], "other_identity": plan["second_identity"],
                       "object_reference": plan["object_reference"]}
        else:
            request = {"vulnerability_class": strategy.vulnerability_class, "hypothesis_id": hid,
                       "evidence": {"baseline_response": first_response_ev, "lower_privilege_response": second_response_ev},
                       "baseline_role": plan["baseline_role"], "comparison_role": plan["comparison_role"],
                       "function_reference": plan["function_reference"]}
        try:
            record = self.engine.validate(request)
        except ValidationError as exc:
            self._close_task(task_id, subset, ok=False, evidence_refs=all_refs, summary="Validation could not run.")
            return self._inconclusive("validation_error", [evidence_request(
                "reproduce_evidence", redact(str(exc))[:200])], evidence_refs=all_refs,
                execution_id=second_result.get("execution_id"), task_id=task_id, executed=True)

        finding_id = finding_status = None
        if record.disposition == SUPPORTED:
            finding_id, finding_status = self._confirm(hypothesis, strategy, plan, record, request, all_refs)
        self._project(plan, first_result, second_result)
        self._close_task(task_id, subset, ok=True, evidence_refs=all_refs,
                         summary=f"Comparison validated as {record.disposition}.")
        self.audit("pipeline.hypothesis_executed", {"hypothesis_id": hid, "tool_id": tool["tool_id"],
                                                    "disposition": record.disposition, "task_id": task_id})
        return {"disposition": record.disposition, "reason": record.explanation, "evidence_refs": all_refs,
                "validation_record_id": record.record_id, "evidence_requests": record.evidence_requests,
                "execution_id": second_result.get("execution_id"),
                "execution_ids": [first_result.get("execution_id"), second_result.get("execution_id")],
                "task_id": task_id, "tool_id": tool["tool_id"], "finding_id": finding_id,
                "finding_status": finding_status}

    # -- lifecycle and graph ---------------------------------------------------------------------------
    def _confirm(self, hypothesis, strategy, plan, record, request, evidence_refs):
        """A supported hypothesis becomes a finding that an *independent* validator must confirm."""
        finding_id = new_id("finding")
        node = plan["endpoint"]
        self.store.record_finding({
            "finding_id": finding_id, "engagement_id": self.engagement_id,
            "title": f"{strategy.title}: {node['key']}", "status": "hypothesis",
            "severity": hypothesis.get("risk", "unknown"), "asset": node["attributes"]["origin"],
            "method": plan["method"], "description": record.explanation,
            "preconditions": list(hypothesis.get("preconditions", [])),
            "proposed_by": self.PROPOSER, "evidence_refs": list(evidence_refs)})
        self.store.transition_finding(finding_id, "validation_pending", self.PROPOSER)
        result = self.finding_validator.validate_finding(finding_id, dict(request), self.VALIDATOR)
        if result["finding_status"] == "validated":
            graph_finding = self.graph.upsert_node(
                "finding", finding_id, label=strategy.title, trust="observed",
                attributes={"status": "validated", "category": strategy.category},
                provenance=[{"source": "validation-engine", "record": record.record_id}], confidence=0.9)
            self.graph.upsert_edge(graph_finding, "TARGETS", node["node_id"], trust="observed",
                                   provenance=[{"source": "validation-engine"}])
            for ref in evidence_refs:
                evidence = self.graph.upsert_node("evidence", str(ref), trust="observed",
                                                  provenance=[{"source": "pipeline"}], confidence=0.6)
                self.graph.upsert_edge(graph_finding, "VALIDATED_BY", evidence, trust="observed",
                                       provenance=[{"source": "validation-engine", "record": record.record_id}],
                                       evidence_refs=[str(ref)])
        return finding_id, result["finding_status"]

    def _project(self, plan, first_result, second_result):
        """Fold what was actually observed back into the graph (evidence-linked, observed trust)."""
        node = plan["endpoint"]
        for identity, result in ((plan["first_identity"], first_result), (plan["second_identity"], second_result)):
            status = result.get("status_code")
            if isinstance(status, int) and 200 <= status < 300:
                try:
                    self.ingestor.observe_access(identity, node["node_id"],
                                                 evidence_refs=result.get("evidence_refs", []), source="pipeline")
                except IngestError:
                    self.audit("pipeline.identity_not_in_graph", {"identity": identity})
