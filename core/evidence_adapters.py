"""Import redacted SARIF, OWASP ZAP JSON, Burp XML and Nessus (.nessus) into the Evidence Vault.

These adapters normalize scanner output into evidence artifacts and hypotheses.
They never execute tests or mark findings as validated.
"""
from __future__ import annotations
import base64
import json
import xml.etree.ElementTree as ET
from pathlib import Path

class EvidenceAdapterError(ValueError):
    pass

def _capture(vault, engagement_id, captured_by, kind, filename, content, redacted):
    if redacted is not True:
        raise EvidenceAdapterError("Scanner imports must be explicitly redacted before ingestion")
    if isinstance(content, str):
        content = content.encode("utf-8")
    return vault.capture(engagement_id, kind, filename, content, captured_by, redacted=True)

def import_sarif(vault, engagement_id, sarif, captured_by, redacted=False):
    if isinstance(sarif, (str, bytes)):
        try:
            sarif = json.loads(sarif)
        except (ValueError, TypeError) as exc:
            raise EvidenceAdapterError("Invalid SARIF JSON") from exc
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise EvidenceAdapterError("SARIF document must contain runs")
    imported = []
    for run_index, run in enumerate(sarif["runs"]):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result_index, result in enumerate(run.get("results", [])):
            rule = rules.get(result.get("ruleId"), {})
            locations = result.get("locations", [])
            physical = (locations[0].get("physicalLocation", {}) if locations else {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            uri = artifact.get("uri", "unknown")
            excerpt = region.get("snippet", {}).get("text")
            if excerpt is None:
                excerpt = json.dumps({"uri": uri, "region": region}, sort_keys=True)
            excerpt_ref = _capture(vault, engagement_id, captured_by, "source_excerpt",
                f"sarif-{run_index}-{result_index}-source.txt", excerpt, redacted)
            refs = [excerpt_ref["evidence_id"]]
            flows = result.get("codeFlows", [])
            if flows:
                flow_text = json.dumps(flows, sort_keys=True)
                flow_ref = _capture(vault, engagement_id, captured_by, "call_graph",
                    f"sarif-{run_index}-{result_index}-flow.json", flow_text, redacted)
                refs.append(flow_ref["evidence_id"])
            imported.append({"source":"sarif","rule_id":result.get("ruleId"),
                "title":rule.get("shortDescription",{}).get("text",result.get("message",{}).get("text","SAST result")),
                "asset":uri,"message":result.get("message",{}).get("text",""),
                "severity":result.get("level","unknown"),"evidence_refs":refs,
                "status":"hypothesis","proposed_by":"sast-import-adapter"})
    return imported

def import_zap_json(vault, engagement_id, document, captured_by, redacted=False):
    if isinstance(document, (str, bytes)):
        try:
            document = json.loads(document)
        except (ValueError, TypeError) as exc:
            raise EvidenceAdapterError("Invalid ZAP JSON") from exc
    alerts = document.get("site") if isinstance(document, dict) else None
    if not isinstance(alerts, list):
        raise EvidenceAdapterError("ZAP JSON must contain a site array")
    imported=[]
    for site_index, site in enumerate(alerts):
        for alert_index, alert in enumerate(site.get("alerts", [])):
            refs=[]
            for instance_index, instance in enumerate(alert.get("instances", [])):
                request=instance.get("request") or instance.get("requestHeader")
                response=instance.get("response") or instance.get("responseHeader")
                if request:
                    refs.append(_capture(vault,engagement_id,captured_by,"http_request",
                        f"zap-{site_index}-{alert_index}-{instance_index}-request.txt",request,redacted)["evidence_id"])
                if response:
                    refs.append(_capture(vault,engagement_id,captured_by,"http_response",
                        f"zap-{site_index}-{alert_index}-{instance_index}-response.txt",response,redacted)["evidence_id"])
            if not refs:
                raw=json.dumps(alert,sort_keys=True)
                refs.append(_capture(vault,engagement_id,captured_by,"scanner_output",
                    f"zap-{site_index}-{alert_index}.json",raw,redacted)["evidence_id"])
            imported.append({"source":"owasp-zap","title":alert.get("name","ZAP alert"),
                "asset":site.get("@name","unknown"),"url":(alert.get("instances") or [{}])[0].get("uri"),
                "risk":alert.get("riskdesc"),"description":alert.get("desc",""),
                "evidence_refs":refs,"status":"hypothesis","proposed_by":"dast-import-adapter"})
    return imported

def import_burp_xml(vault, engagement_id, xml_bytes, captured_by, redacted=False):
    if redacted is not True:
        raise EvidenceAdapterError("Burp imports must be explicitly redacted before ingestion")
    try:
        root=ET.fromstring(xml_bytes)
    except (ET.ParseError, TypeError) as exc:
        raise EvidenceAdapterError("Invalid Burp XML export") from exc
    imported=[]
    for index, issue in enumerate(root.findall(".//issue")):
        refs=[]
        for item_index, item in enumerate(issue.findall("./http-messages/item")):
            for tag, kind in (("request","http_request"),("response","http_response")):
                node=item.find(tag)
                if node is None or not node.text:
                    continue
                try:
                    payload=base64.b64decode(node.text,validate=True)
                except Exception:
                    payload=node.text.encode()
                refs.append(_capture(vault,engagement_id,captured_by,kind,
                    f"burp-{index}-{item_index}-{tag}.txt",payload,redacted)["evidence_id"])
        if not refs:
            refs.append(_capture(vault,engagement_id,captured_by,"scanner_output",
                f"burp-{index}-issue.xml",ET.tostring(issue,encoding="utf-8"),redacted)["evidence_id"])
        imported.append({"source":"burp","title":issue.findtext("name","Burp issue"),
            "asset":issue.findtext("host","unknown"),"path":issue.findtext("path",""),
            "severity":issue.findtext("severity","unknown"),"description":issue.findtext("issueBackground",""),
            "evidence_refs":refs,"status":"hypothesis","proposed_by":"dast-import-adapter"})
    return imported


_NESSUS_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def import_nessus(vault, engagement_id, xml_bytes, captured_by, redacted=False):
    if redacted is not True:
        raise EvidenceAdapterError("Nessus imports must be explicitly redacted before ingestion")
    try:
        root = ET.fromstring(xml_bytes)
    except (ET.ParseError, TypeError) as exc:
        raise EvidenceAdapterError("Invalid Nessus (.nessus) XML export") from exc
    imported = []
    for host in root.findall(".//ReportHost"):
        host_name = host.get("name", "unknown")
        for index, item in enumerate(host.findall("./ReportItem")):
            severity = _NESSUS_SEVERITY.get(item.get("severity", "0"), "unknown")
            ref = _capture(vault, engagement_id, captured_by, "scanner_output",
                           f"nessus-{host_name}-{index}.xml",
                           ET.tostring(item, encoding="utf-8"), redacted)["evidence_id"]
            imported.append({"source": "nessus", "title": item.get("pluginName", "Nessus item"),
                             "asset": host_name, "port": item.get("port"),
                             "plugin_id": item.get("pluginID"), "severity": severity,
                             "description": (item.findtext("description", "") or "")[:2000],
                             "evidence_refs": [ref], "status": "hypothesis",
                             "proposed_by": "vuln-scan-import-adapter"})
    return imported
