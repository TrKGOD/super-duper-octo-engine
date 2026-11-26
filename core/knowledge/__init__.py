"""Knowledge Intelligence (RAG).

Extends the existing FTS Knowledge Base with multi-format ingestion, taxonomy reference
extraction (CWE/CVE/OWASP/CAPEC/ATT&CK), and a retrieval API offering an always-functional
FTS baseline plus an optional embedding backend and per-agent contextual retrieval.
Retrieved knowledge is untrusted context with provenance; it provides knowledge, never
authorization.
"""
from core.knowledge.graph_bridge import (KnowledgeGraphBridge, KnowledgeGraphError,
                                         patterns_for_endpoint, patterns_for_technology,
                                         patterns_for_vulnerability_class,
                                         tools_for_vulnerability_class, weaknesses_of_pattern)
from core.knowledge.ingest import (IngestError, documents_with_reference, extract_text,
                                    ingest_content, record_references, references_for)
from core.knowledge.retrieval import (AGENT_PROFILES, ContextualRetriever, KnowledgeRetriever,
                                      MAX_CONTEXT_ITEMS)
from core.knowledge.taxonomy import extract_references, merge_references, REFERENCE_TYPES

__all__ = [
    "extract_text", "ingest_content", "IngestError", "references_for", "record_references",
    "documents_with_reference", "KnowledgeRetriever", "ContextualRetriever", "AGENT_PROFILES",
    "MAX_CONTEXT_ITEMS", "extract_references", "merge_references", "REFERENCE_TYPES",
    "KnowledgeGraphBridge", "KnowledgeGraphError", "patterns_for_endpoint",
    "patterns_for_technology", "patterns_for_vulnerability_class",
    "tools_for_vulnerability_class", "weaknesses_of_pattern",
]
