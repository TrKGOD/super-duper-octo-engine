"""Knowledge Intelligence (Component A / RAG) tests.

Covers taxonomy reference extraction, multi-format ingestion (HTML/JSON/JSONL/XML) with
safe tag-stripping (no XXE), taxonomy enrichment and dedup, the FTS retrieval baseline with
provenance and the untrusted-knowledge marker, the optional embedding seam, and per-agent
contextual retrieval with its item budget. Uses a temporary KB database; no network.
"""
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts.knowledge_base import connect, init_db, import_pattern
from core.knowledge import (ContextualRetriever, IngestError, KnowledgeRetriever,
                           documents_with_reference, extract_references, extract_text,
                           ingest_content, merge_references, references_for)

META = {"title": "Example", "platform": "Test fixture", "source_url": "https://example.org/a",
        "disclosure_status": "public", "rights_basis": "Fixture authored for this unit test.",
        "collected_at": "2026-11-26T00:00:00Z", "published_at": None, "content_type": "research_summary",
        "vulnerability_types": [], "technologies": [], "asset_types": ["api"], "tags": ["knowledge"],
        "author": None, "license": "CC0-1.0", "notes": None}


def meta(**over):
    return {**META, **over}


def stable_embedder(text, dim=24):
    vec = [0.0] * dim
    for word in re.findall(r"[a-z0-9]+", str(text).lower()):
        vec[int(hashlib.md5(word.encode()).hexdigest(), 16) % dim] += 1.0
    return vec


class TaxonomyTests(unittest.TestCase):
    def test_extracts_and_normalizes_references(self):
        refs = extract_references("Impacted by CVE-2021-44228 and cwe-639; OWASP A01:2021; "
                                  "CAPEC-66; MITRE T1190.001 technique.")
        self.assertEqual(refs["cve"], ["CVE-2021-44228"])
        self.assertEqual(refs["cwe"], ["CWE-639"])
        self.assertEqual(refs["owasp"], ["A01:2021"])
        self.assertEqual(refs["capec"], ["CAPEC-66"])
        self.assertEqual(refs["attack"], ["T1190.001"])

    def test_bare_timestamp_is_not_owasp(self):
        self.assertNotIn("owasp", extract_references("logged at 01:2021 hours"))

    def test_merge_references(self):
        merged = merge_references({"cwe": ["CWE-79"]}, {"cwe": ["cwe-89"], "cve": ["CVE-2020-1"]})
        self.assertEqual(merged["cwe"], ["CWE-79", "CWE-89"])
        self.assertEqual(merged["cve"], ["CVE-2020-1"])


class KBTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = connect(Path(self.tmp.name) / "kb.sqlite")
        init_db(self.db)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()  # ignore_cleanup_errors handles Windows sqlite file locks


class IngestionTests(KBTestBase):
    def test_html_is_tag_stripped_and_scripts_dropped(self):
        html = ("<html><body><h1>SSRF</h1><p>See CWE-918 for server side request forgery.</p>"
                "<script>steal()</script></body></html>")
        doc_id = ingest_content(self.db, html, "text/html", meta(title="HTML doc"))
        self.assertIn("cwe", references_for(self.db, doc_id))
        self.assertEqual(references_for(self.db, doc_id)["cwe"], ["CWE-918"])
        content = self.db.execute("SELECT content FROM kb_documents WHERE document_id=?", (doc_id,)).fetchone()["content"]
        self.assertIn("SSRF", content)
        self.assertNotIn("steal()", content)        # script contents dropped

    def test_json_and_jsonl_and_xml(self):
        j = ingest_content(self.db, json.dumps({"vuln": "IDOR", "ref": "CWE-639"}),
                           "application/json", meta(title="json"))
        self.assertEqual(references_for(self.db, j)["cwe"], ["CWE-639"])
        jl = ingest_content(self.db, '{"a":"CVE-2019-1001"}\n{"b":"CVE-2019-1002"}',
                            "application/jsonl", meta(title="jsonl"))
        self.assertEqual(references_for(self.db, jl)["cve"], ["CVE-2019-1001", "CVE-2019-1002"])
        xml = ingest_content(self.db, "<r><note>Affects CVE-2020-0001 detail</note></r>",
                             "application/xml", meta(title="xml"))
        self.assertEqual(references_for(self.db, xml)["cve"], ["CVE-2020-0001"])

    def test_xml_entities_are_not_expanded(self):
        xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "SECRETLEAK">]>'
               '<r>&x; mentions CVE-2020-0001</r>')
        text = extract_text(xxe, "application/xml")
        self.assertNotIn("SECRETLEAK", text)        # entity never resolved
        self.assertIn("CVE-2020-0001", text)

    def test_dedup_on_content_hash(self):
        first = ingest_content(self.db, "duplicate body CWE-1", "text/plain", meta(title="d1"))
        second = ingest_content(self.db, "duplicate body CWE-1", "text/plain", meta(title="d2"))
        self.assertEqual(first, second)

    def test_unsupported_and_pdf_raise(self):
        with self.assertRaises(IngestError):
            ingest_content(self.db, "x", "application/zip", meta())
        with self.assertRaises(IngestError):
            extract_text(b"%PDF-1.4", "application/pdf")

    def test_documents_with_reference(self):
        doc_id = ingest_content(self.db, "contains CWE-352 csrf", "text/plain", meta(title="csrf"))
        self.assertEqual(documents_with_reference(self.db, "cwe", "CWE-352"), [doc_id])


class RetrievalTests(KBTestBase):
    def _seed_pattern(self, doc_id):
        pattern = {"pattern_id": "PAT-1", "document_id": doc_id, "vulnerability_type": "BOLA",
                   "root_cause": "Missing object-level authorization check.",
                   "preconditions": ["Two synthetic identities"],
                   "reproduction_summary": "Compare object access across two lab identities.",
                   "evidence_summary": "Cross-identity object response observed.",
                   "impact": "Access to another tenant's object.",
                   "remediation": "Enforce server-side object authorization.",
                   "false_positives": [], "confidence": "high", "source_spans": ["BOLA section"],
                   "domain": "api", "tags": ["authorization", "idor"]}
        path = Path(self.tmp.name) / "pat.json"
        path.write_text(json.dumps(pattern), encoding="utf-8")
        import_pattern(self.db, str(path))

    def test_document_retrieval_has_provenance_and_untrusted_marker(self):
        ingest_content(self.db, "BOLA authorization object reference in REST APIs", "text/plain",
                       meta(title="BOLA doc", vulnerability_types=["BOLA"]))
        results = KnowledgeRetriever(self.db).retrieve_documents("BOLA")
        self.assertTrue(results)
        self.assertEqual(results[0]["trust"], "untrusted_knowledge")
        self.assertTrue(results[0]["provenance"]["source_url"])
        self.assertIn("confers no", results[0]["note"])

    def test_pattern_retrieval(self):
        doc_id = ingest_content(self.db, "BOLA writeup body", "text/plain", meta(title="BOLA"))
        self._seed_pattern(doc_id)
        results = KnowledgeRetriever(self.db).retrieve_patterns("BOLA authorization", domain="api")
        self.assertTrue(results)
        self.assertEqual(results[0]["retrieval_kind"], "pattern")

    def test_empty_query_returns_nothing(self):
        self.assertEqual(KnowledgeRetriever(self.db).retrieve_documents("   "), [])


class EmbeddingSeamTests(KBTestBase):
    def test_semantic_retrieval_with_injected_embedder(self):
        ingest_content(self.db, "server side request forgery to cloud metadata endpoint", "text/plain",
                       meta(title="ssrf"), embedder=stable_embedder)
        ingest_content(self.db, "reflected cross site scripting in search box", "text/plain",
                       meta(title="xss"), embedder=stable_embedder)
        retriever = KnowledgeRetriever(self.db, embedder=stable_embedder)
        results = retriever.semantic_documents("server side request forgery metadata")
        self.assertTrue(results)
        self.assertEqual(results[0]["title"], "ssrf")

    def test_semantic_is_empty_without_embedder(self):
        ingest_content(self.db, "anything", "text/plain", meta(title="x"))
        self.assertEqual(KnowledgeRetriever(self.db).semantic_documents("anything"), [])


class ContextualRetrievalTests(KBTestBase):
    def setUp(self):
        super().setUp()
        ingest_content(self.db, "BOLA object reference authorization REST API idor", "text/plain",
                       meta(title="doc", vulnerability_types=["BOLA"]))
        doc_id = self.db.execute("SELECT document_id FROM kb_documents LIMIT 1").fetchone()["document_id"]
        pattern = {"pattern_id": "PAT-C", "document_id": doc_id, "vulnerability_type": "BOLA",
                   "root_cause": "Missing object-level authorization check.",
                   "preconditions": ["Two synthetic identities"],
                   "reproduction_summary": "Compare object access across two lab identities.",
                   "evidence_summary": "Cross-identity object response observed in lab.",
                   "impact": "Access to another tenant object.",
                   "remediation": "Enforce server-side object authorization.",
                   "false_positives": [], "confidence": "high", "source_spans": ["BOLA section"],
                   "domain": "api", "tags": ["idor"]}
        path = Path(self.tmp.name) / "p.json"
        path.write_text(json.dumps(pattern), encoding="utf-8")
        import_pattern(self.db, str(path))
        self.ctx = ContextualRetriever(KnowledgeRetriever(self.db))

    def test_vulnerability_agent_gets_patterns(self):
        result = self.ctx.for_task(agent="vulnerability-agent", query="idor authorization",
                                   vulnerability_classes=["idor"], domain="api")
        self.assertTrue(result["patterns"])
        self.assertEqual(result["documents"], [])      # profile kind is 'patterns'
        self.assertIn("confers no", result["note"])

    def test_recon_agent_gets_documents(self):
        result = self.ctx.for_task(agent="recon-agent", query="BOLA object reference")
        self.assertEqual(result["patterns"], [])
        self.assertTrue(result["documents"])

    def test_item_budget_is_capped(self):
        result = self.ctx.for_task(agent="enumeration-agent", query="idor", limit=100)
        self.assertLessEqual(result["limit"], 8)


if __name__ == "__main__":
    unittest.main()
