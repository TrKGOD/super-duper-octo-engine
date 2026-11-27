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
import html
import json
import os
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

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
from core.planner.candidates import _SSRF_HINTS, _is_state_changing
from core.planner.hypothesis import HypothesisStore
from core.redaction import redact
from core.security_testing import (execute_readonly_pair, load_marker_matched_callback_events,
                                   redact_callback_events, validate_scoped_callback_url)
from core.store import new_id
from core.tools.profiles import ProfilePolicy
from core.tools.selection import CapabilityRequest, ToolSelector
from core.validation_engine import (EvidenceResolver, ExploitValidationEngine, FindingValidator,
                                    GraphFacts, SUPPORTED, ValidationError, ValidationRecordStore)
from core.validation_engine.oracles import evidence_request

_READ_METHODS = ("GET", "HEAD")

# SQLi: one well-known, non-destructive boolean-differential technique -- see core/pipeline/strategies.py
# for the full statement of what this deliberately does not cover.
_SQLI_BASELINE_VALUE = "1"
_SQLI_TRUE_VALUE = "1' OR '1'='1"
_SQLI_FALSE_VALUE = "1' OR '1'='2"


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
        self.rules = json.loads(row["rules_json"])
        self.selector = ToolSelector(self.registry, ProfilePolicy(self.rules))
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
        if strategy.category in ("idor_bola", "bfla"):
            return self._execute_pair(hypothesis, strategy, tool, plan)
        return getattr(self, "_execute_" + strategy.category)(hypothesis, strategy, tool, plan)

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

    @staticmethod
    def _parameter_name(param: dict) -> str:
        # Discovery paths disagree on where the name lives: core/pipeline/discovery.py (the
        # same-origin crawler AssessmentPipeline.discover() uses) sets only ``label``, leaving
        # ``attributes`` empty; core/graph/ingest.py's browser-report path sets attributes["name"]
        # too. core/planner/candidates.py already reads ``label`` first for the same reason.
        return str(param.get("label") or param["attributes"].get("name") or param["key"])

    def _query_parameters(self, node) -> list:
        """Parameter nodes this endpoint accepts, reachable via ACCEPTS. Safe to place in a query
        string once the endpoint itself is confirmed not state-changing (GET/HEAD) -- a GET-method
        HTML form's fields become a query string too when submitted. Call only after that check:
        it is the actual safety gate, not whatever label discovery happened to give one parameter."""
        params = [self.graph.get_node_by_id(edge["dst"])
                 for edge in self.graph.edges("ACCEPTS", src_id=node["node_id"])]
        params = [p for p in params if p and p["node_type"] == "parameter"]
        return sorted(params, key=self._parameter_name)

    def _query_url(self, node, params: list, candidate: dict, candidate_value: str) -> str:
        """``origin+path?...`` with every declared parameter present; only ``candidate`` carries
        the probe value, everything else gets an inert synthetic placeholder."""
        attrs = node["attributes"]
        base = attrs["origin"].rstrip("/") + (attrs.get("path") or "/")
        query = [(self._parameter_name(p), candidate_value if p is candidate else "1") for p in params]
        return base + "?" + urlencode(query)

    # -- a single-endpoint hypothesis shared by sqli/xss/ssrf: target, parameter, identity -------
    def _plan_single_parameter_probe(self, hypothesis, *, select_candidate, not_found_reason, not_found_detail):
        node = self._endpoint(hypothesis)
        if node is None:
            return {"reason": "target_missing", "needs": [evidence_request(
                "select_target_endpoint", "an in-scope endpoint is required")]}
        if _is_state_changing(node):
            return {"reason": "state_changing_endpoint", "needs": [evidence_request(
                "operator_pinned_manifests", "automated testing of this class is limited to non-state-changing "
                "(GET/HEAD) endpoints; a state-changing target needs an individually approved request",
                method=node["attributes"].get("method", "GET"))]}
        params = self._query_parameters(node)
        candidate = select_candidate(params)
        if candidate is None:
            return {"reason": not_found_reason, "needs": [evidence_request(
                "identify_candidate_parameter", not_found_detail, endpoint=node["key"])]}
        actor = hypothesis.get("required_identity")
        missing = self._needs_credentials(actor) if actor else None
        if missing:
            return missing
        return {"endpoint": node, "params": params, "candidate": candidate, "identity": actor, "method": "GET"}

    def _plan_sqli(self, hypothesis) -> dict:
        plan = self._plan_single_parameter_probe(
            hypothesis, select_candidate=lambda params: params[0] if params else None,
            not_found_reason="no_query_parameter",
            not_found_detail="the endpoint has no declared query (or GET-form) parameter; form POST bodies, "
                             "JSON bodies and headers are not automated in this release")
        if "needs" in plan:
            return plan
        node, params, candidate = plan["endpoint"], plan["params"], plan["candidate"]
        plan["urls"] = {
            "baseline": self._query_url(node, params, candidate, _SQLI_BASELINE_VALUE),
            "true_case": self._query_url(node, params, candidate, _SQLI_TRUE_VALUE),
            "false_case": self._query_url(node, params, candidate, _SQLI_FALSE_VALUE)}
        return plan

    def _plan_xss(self, hypothesis) -> dict:
        plan = self._plan_single_parameter_probe(
            hypothesis, select_candidate=lambda params: params[0] if params else None,
            not_found_reason="no_query_parameter",
            not_found_detail="the endpoint has no declared query (or GET-form) parameter; form POST bodies, "
                             "JSON bodies and headers are not automated in this release")
        if "needs" in plan:
            return plan
        node, params, candidate = plan["endpoint"], plan["params"], plan["candidate"]
        marker = "<wh-xss-" + uuid.uuid4().hex[:16] + ">"
        plan["marker"] = marker
        plan["url"] = self._query_url(node, params, candidate, marker)
        return plan

    def _plan_ssrf(self, hypothesis) -> dict:
        def select_url_like(params):
            matches = [p for p in params
                      if any(hint in self._parameter_name(p).lower() for hint in _SSRF_HINTS)]
            return matches[0] if matches else None

        plan = self._plan_single_parameter_probe(
            hypothesis, select_candidate=select_url_like, not_found_reason="no_url_like_parameter",
            not_found_detail="no declared query (or GET-form) parameter name matches a URL-fetch hint")
        if "needs" in plan:
            return plan
        callback_url = self.rules.get("ssrf_callback_url")
        if not callback_url:
            return {"reason": "ssrf_callback_not_configured", "needs": [evidence_request(
                "configure_ssrf_callback", "set rules_of_engagement.ssrf_callback_url to an operator-run, "
                "scope-listed HTTPS listener before SSRF hypotheses can be executed automatically; this "
                "framework never hosts the listener itself")]}
        try:
            validate_scoped_callback_url(callback_url, self.scope)
        except ActiveExecutionError as exc:
            return {"reason": "ssrf_callback_out_of_scope", "needs": [evidence_request(
                "configure_ssrf_callback", redact(str(exc))[:200])]}
        node, params, candidate = plan["endpoint"], plan["params"], plan["candidate"]
        marker = "wh-ssrf-" + uuid.uuid4().hex[:16]
        separator = "&" if "?" in callback_url else "?"
        plan["marker"] = marker
        plan["callback_events_path"] = self.rules.get("ssrf_callback_events_path")
        plan["url"] = self._query_url(node, params, candidate, f"{callback_url}{separator}wh={marker}")
        return plan

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

    def _manifest(self, request_id: str, plan: dict, identity: str, hypothesis_id: str, *,
                 purpose: str = "authorization comparison") -> dict:
        manifest = {"request_id": request_id, "method": plan["method"], "url": plan["url"],
                   "purpose": f"Authorized read-only {purpose} for hypothesis {hypothesis_id[4:16]} "
                              "(deterministic pipeline)",
                   "timeout_seconds": 8, "max_response_bytes": 65536, "follow_redirects": False}
        secret_headers = self.identities.secret_headers(identity) if identity else None
        if secret_headers is not None:   # the schema requires an object when present; omit, never null, when anonymous
            manifest["secret_headers"] = secret_headers
        return manifest

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

    # -- execution shared by sqli/xss/ssrf: N named, read-only GET requests pinned in one task -----
    def _execute_requests(self, hid: str, subset: list, identity, urls: dict, *, purpose: str) -> dict:
        """Run each ``{role: url}`` request in a fixed (sorted) order, never re-sending on failure.

        Returns ``{"ok", "task_id", "results": {role: execute_request_file() result}, "evidence_refs"}``;
        on failure ``"ok"`` is False and ``"error"`` is a ready-made evidence_request.
        """
        nonce = uuid.uuid4().hex[:10]
        roles = sorted(urls)
        manifests = {role: self._manifest(f"pl-{nonce}-{index}", {"method": "GET", "url": urls[role]},
                                          identity, hid, purpose=purpose) for index, role in enumerate(roles)}
        try:
            pinned = {role: self._pin(manifests[role]) for role in roles}
            created = self.workflow.create_plan(self.engagement_id, {"tasks": [{
                "task_key": f"pipeline-{hid[4:16]}-{nonce}", "agent": self.AGENT,
                "objective": f"Execute {len(roles)} read-only request(s) for hypothesis {hid[4:16]}",
                "completion_criteria": ["Every pinned request executed through the broker with evidence"],
                "scope_subset": subset, "domain": "web", "skill_tags": ["http-read-only"],
                "active_testing": True, "request_files": [pinned[role] for role in roles]}]})
            task_id = created[0]["task_id"]
            self.workflow.start_task(task_id, model="deterministic-pipeline")
            # Linked before anything is sent: if this process dies mid-way, recovery can still find
            # the executions that may already have reached the target.
            HypothesisStore(self.store.connection, self.engagement_id).set_last_execution(hid, "task:" + task_id)
        except (WorkflowError, ActiveExecutionError, OSError) as exc:
            return {"ok": False, "task_id": None, "results": {}, "evidence_refs": [], "error": evidence_request(
                "plan_refused", redact(str(exc))[:200], failure_class=classify_exception(exc))}

        results: dict = {}
        refs: list = []
        for role in roles:
            try:
                results[role] = self.http.execute_request_file(self.engagement_id, task_id, pinned[role]["path"])
                refs.extend(results[role].get("evidence_refs", []))
            except ActiveExecutionError as exc:
                self._close_task(task_id, subset, ok=False, evidence_refs=refs,
                                 summary="Execution was refused: " + redact(str(exc))[:160])
                return {"ok": False, "task_id": task_id, "results": results, "evidence_refs": refs,
                        "error": evidence_request("execution_refused", redact(str(exc))[:200],
                                                   failure_class=classify_exception(exc))}
        return {"ok": True, "task_id": task_id, "results": results, "evidence_refs": list(dict.fromkeys(refs))}

    def _validate_and_finish(self, hypothesis, strategy, tool, plan, subset: list, request: dict, outcome: dict) -> dict:
        """Validate, confirm on SUPPORTED, close the task, audit — the tail every single-endpoint
        probe (sqli/xss/ssrf) shares once it has built its own ``request`` and run ``outcome``."""
        hid, task_id, evidence_refs = hypothesis["hypothesis_id"], outcome["task_id"], outcome["evidence_refs"]
        try:
            record = self.engine.validate(request)
        except ValidationError as exc:
            self._close_task(task_id, subset, ok=False, evidence_refs=evidence_refs, summary="Validation could not run.")
            return self._inconclusive("validation_error", [evidence_request("reproduce_evidence", redact(str(exc))[:200])],
                                      evidence_refs=evidence_refs, task_id=task_id, executed=True)
        finding_id = finding_status = None
        if record.disposition == SUPPORTED:
            finding_id, finding_status = self._confirm(hypothesis, strategy, plan, record, request, evidence_refs)
        self._close_task(task_id, subset, ok=True, evidence_refs=evidence_refs,
                         summary=f"{strategy.title} probe validated as {record.disposition}.")
        self.audit("pipeline.hypothesis_executed", {"hypothesis_id": hid, "tool_id": tool["tool_id"],
                                                    "disposition": record.disposition, "task_id": task_id})
        return {"disposition": record.disposition, "reason": record.explanation, "evidence_refs": evidence_refs,
                "validation_record_id": record.record_id, "evidence_requests": record.evidence_requests,
                "task_id": task_id, "tool_id": tool["tool_id"], "finding_id": finding_id,
                "finding_status": finding_status}

    def _execute_sqli(self, hypothesis, strategy, tool, plan) -> dict:
        subset = self._scope_subset(plan["urls"]["baseline"])
        if not subset:
            return self._inconclusive("target_outside_engagement_assets", [evidence_request(
                "scope_review", "the target is not covered by an explicit engagement asset")])
        hid = hypothesis["hypothesis_id"]
        outcome = self._execute_requests(hid, subset, plan["identity"], plan["urls"],
                                         purpose="SQL-injection boolean-pair probe")
        if not outcome["ok"]:
            return self._inconclusive(outcome["error"]["kind"], [outcome["error"]], task_id=outcome["task_id"],
                                      evidence_refs=outcome["evidence_refs"], executed=bool(outcome["task_id"]))
        results = outcome["results"]
        # The oracle compares response FINGERPRINTS: an endpoint that simply echoes its input
        # will always fingerprint true_case and false_case differently, since the two payload
        # STRINGS differ -- with nothing to do with SQL logic. Caught here, before validation,
        # because this is a property of what the target did with THESE specific requests, not
        # something the general-purpose oracle (reused as-is) can tell apart. Checked against
        # both the raw payload and its HTML-escaped form, the two transforms this pipeline's own
        # XSS probe already distinguishes; a different output encoding could still go undetected.
        def _reflects(result: dict, payload: str) -> bool:
            body = result.get("response_excerpt") or ""
            return payload in body or html.escape(payload) in body

        if _reflects(results["true_case"], _SQLI_TRUE_VALUE) and _reflects(results["false_case"], _SQLI_FALSE_VALUE):
            self._close_task(outcome["task_id"], subset, ok=True, evidence_refs=outcome["evidence_refs"],
                             summary="The endpoint reflects the probe value (raw or HTML-escaped); a boolean "
                                     "differential there cannot be trusted as a SQL-injection signal.")
            return self._inconclusive("reflection_confound", [evidence_request(
                "possible_reflection_confound",
                "the true_case and false_case payloads were each found reflected (raw or HTML-escaped) in "
                "their own response; any difference between them may simply be echoed input text, not SQL "
                "logic -- manual review (or a different, non-reflecting candidate parameter) is needed")],
                evidence_refs=outcome["evidence_refs"], task_id=outcome["task_id"], executed=True)
        request = {"vulnerability_class": "sqli", "hypothesis_id": hid, "evidence": {
            role: results[role]["evidence_refs"][1] for role in ("baseline", "true_case", "false_case")}}
        return self._validate_and_finish(hypothesis, strategy, tool, plan, subset, request, outcome)

    def _execute_xss(self, hypothesis, strategy, tool, plan) -> dict:
        subset = self._scope_subset(plan["url"])
        if not subset:
            return self._inconclusive("target_outside_engagement_assets", [evidence_request(
                "scope_review", "the target is not covered by an explicit engagement asset")])
        hid = hypothesis["hypothesis_id"]
        outcome = self._execute_requests(hid, subset, plan["identity"], {"probe": plan["url"]},
                                         purpose="reflected-input (XSS) marker probe")
        if not outcome["ok"]:
            return self._inconclusive(outcome["error"]["kind"], [outcome["error"]], task_id=outcome["task_id"],
                                      evidence_refs=outcome["evidence_refs"], executed=bool(outcome["task_id"]))
        result = outcome["results"]["probe"]
        request = {"vulnerability_class": "reflected_input", "hypothesis_id": hid, "marker": plan["marker"],
                   "evidence": {"request": result["evidence_refs"][0], "response": result["evidence_refs"][1]}}
        return self._validate_and_finish(hypothesis, strategy, tool, plan, subset, request, outcome)

    def _execute_ssrf(self, hypothesis, strategy, tool, plan) -> dict:
        subset = self._scope_subset(plan["url"])
        if not subset:
            return self._inconclusive("target_outside_engagement_assets", [evidence_request(
                "scope_review", "the target is not covered by an explicit engagement asset")])
        hid = hypothesis["hypothesis_id"]
        outcome = self._execute_requests(hid, subset, plan["identity"], {"probe": plan["url"]},
                                         purpose="SSRF callback probe")
        if not outcome["ok"]:
            return self._inconclusive(outcome["error"]["kind"], [outcome["error"]], task_id=outcome["task_id"],
                                      evidence_refs=outcome["evidence_refs"], executed=bool(outcome["task_id"]))
        result = outcome["results"]["probe"]
        events_path = plan.get("callback_events_path")
        try:
            events = (load_marker_matched_callback_events(events_path, self.project_root, plan["marker"])
                      if events_path else [])
        except (ActiveExecutionError, OSError, ValueError) as exc:
            self._close_task(outcome["task_id"], subset, ok=False, evidence_refs=outcome["evidence_refs"],
                             summary="Callback log could not be read.")
            return self._inconclusive("callback_log_unreadable", [evidence_request(
                "fix_callback_log", redact(str(exc))[:200])], evidence_refs=outcome["evidence_refs"],
                task_id=outcome["task_id"], executed=True)
        # Captured even when empty: the "ssrf" evidence spec always requires this role, so the
        # resolver's own fact (whether the log holds a matching event) is never caller-asserted.
        callback_artifact = self.vault.capture(
            self.engagement_id, "other",
            "ssrf-callback-" + hashlib.sha256(plan["marker"].encode()).hexdigest()[:16] + ".json",
            json.dumps({"events": redact_callback_events(events)}, ensure_ascii=False).encode(),
            self.AGENT, redacted=True, execution_id=result.get("execution_id"), task_id=outcome["task_id"])
        callback_ev = callback_artifact["evidence_id"]
        outcome["evidence_refs"] = list(dict.fromkeys(outcome["evidence_refs"] + [callback_ev]))
        request = {"vulnerability_class": "ssrf", "hypothesis_id": hid, "marker": plan["marker"],
                   "evidence": {"response": result["evidence_refs"][1], "callback_log": callback_ev}}
        return self._validate_and_finish(hypothesis, strategy, tool, plan, subset, request, outcome)

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
