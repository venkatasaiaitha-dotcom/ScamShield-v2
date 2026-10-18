"""
ScamShield Graph — Investigation Agent
Track 1: Agents That Act on Connected Data.

The Investigation Agent receives ScamShield detector output, identifies critical threat
indicators (domains, phone numbers, VPAs, threat patterns), coordinates parameterized Cypher
queries against FalkorDB, and synthesizes grounded, explainable evidence reports.
"""

import logging
from typing import Dict, Any, List, Optional

from ..services.graph_service import graph_service, FalkorDBUnavailableError
from ..ml.classifier import classifier

logger = logging.getLogger("scamshield.agent.investigation")


class InvestigationAgent:
    """
    Autonomous Graph Investigation Agent.
    Executes investigative graph queries via FalkorDB tools and produces
    transparent, grounded explanations distinguishing facts, reports, and uncertainty.
    """

    def __init__(self):
        self.graph_service = graph_service

    # =========================================================================
    # TOOL INTERFACE
    # =========================================================================

    def tool_find_shared_indicators(self, message_id: str) -> List[Dict[str, Any]]:
        """Tool 1: Find other messages in FalkorDB sharing the same domain, phone, or indicator."""
        return self.graph_service.find_shared_indicators(message_id)

    def tool_trace_connected_evidence(self, message_id: str) -> Dict[str, Any]:
        """Tool 2: Trace graph relationship paths to threat reports, domains, and organizations."""
        return self.graph_service.trace_connected_evidence(message_id)

    def tool_get_evidence_summary(self, message_id: str) -> Dict[str, Any]:
        """Tool 3: Aggregate shared indicators, threat intelligence reports, and graph paths."""
        shared = self.tool_find_shared_indicators(message_id)
        evidence = self.tool_trace_connected_evidence(message_id)
        return {
            "message_id": message_id,
            "shared_indicators": shared,
            "evidence": evidence
        }

    # =========================================================================
    # INVESTIGATION WORKFLOW
    # =========================================================================

    async def investigate_message(
        self,
        message_id: Optional[str] = None,
        content: Optional[str] = None,
        sender: Optional[str] = None,
        existing_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main investigation orchestrator:
        1. Ensures message and indicators exist in FalkorDB.
        2. Invokes graph tools to discover connected evidence.
        3. Analyzes clusters and shared indicators.
        4. Synthesizes a factual, evidence-grounded explanation.
        """
        # Step 1: Verify FalkorDB connectivity
        is_ok, err_msg = self.graph_service.check_connection()
        if not is_ok:
            raise FalkorDBUnavailableError(err_msg)

        # Step 2: Ensure we have an analysis and message ID
        if not existing_analysis:
            if not content:
                raise ValueError("Either message_id, existing_analysis, or content must be provided.")
            existing_analysis = classifier.process(content, sender or "Manual Inspection")
            target_id = existing_analysis.get("id") or f"msg-{abs(hash(content)) % 1000000}"
            existing_analysis["id"] = target_id
            existing_analysis["sender"] = sender or "Manual Inspection"
        else:
            target_id = message_id or existing_analysis.get("id") or existing_analysis.get("message_id")

        # Step 3: Ingest or update into FalkorDB
        self.graph_service.ingest_analysis_to_graph(existing_analysis, full_content=content)

        # Step 4: Execute graph investigative tools
        shared_indicators = self.tool_find_shared_indicators(target_id)
        evidence_chain = self.tool_trace_connected_evidence(target_id)

        # Step 5: Synthesize Grounded Evidence Report
        return self._synthesize_evidence_report(
            target_id=target_id,
            analysis=existing_analysis,
            shared_indicators=shared_indicators,
            evidence_chain=evidence_chain
        )

    def _synthesize_evidence_report(
        self,
        target_id: str,
        analysis: Dict[str, Any],
        shared_indicators: List[Dict[str, Any]],
        evidence_chain: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Builds a structured, human-readable evidence report grounded strictly
        in the Cypher query outputs from FalkorDB.
        """
        extracted = evidence_chain.get("extracted_entities", {})
        domains = extracted.get("domains", [])
        phones = extracted.get("phones", [])
        orgs = extracted.get("organizations", [])
        indicators = extracted.get("indicators", [])
        threat_reports = evidence_chain.get("threat_reports", [])
        network = evidence_chain.get("network", {"nodes": [], "edges": []})

        # Calculate cluster correlation
        unique_related_messages = {}
        shared_entities_set = set()
        for item in shared_indicators:
            shared_entities_set.add(item["indicator_value"])
            other = item.get("related_message", {})
            other_id = other.get("id")
            if other_id and other_id not in unique_related_messages:
                unique_related_messages[other_id] = other

        related_count = len(unique_related_messages)
        shared_entity_count = len(shared_entities_set)

        # Build Grounded Explanation Narrative
        explanation_paragraphs = []

        # Point 1: Detector Baseline
        baseline_score = analysis.get("risk_score", 0)
        baseline_level = analysis.get("risk_level", "LOW")
        explanation_paragraphs.append(
            f"ScamShield's local heuristic engine assessed this message as {baseline_level} RISK ({baseline_score}/100) "
            f"under the category '{analysis.get('category', 'GENERAL')}'. "
            f"Extracted {len(domains)} domain(s), {len(phones)} phone number(s), and {len(indicators)} security indicator(s)."
        )

        # Point 2: Graph Connectivity & Shared Indicators
        if related_count > 0:
            shared_names_str = ", ".join([f"'{s}'" for s in list(shared_entities_set)[:3]])
            explanation_paragraphs.append(
                f"🔗 GRAPH EVIDENCE UNCOVERED: FalkorDB Cypher queries revealed that this message shares indicators "
                f"({shared_names_str}) with {related_count} other historical message(s) in the database. "
                f"This indicates recurring adversarial infrastructure rather than an isolated incident."
            )
        else:
            explanation_paragraphs.append(
                "🔍 GRAPH OBSERVATION: No prior messages in the graph currently share these exact identifiers. "
                "This appears to be a newly observed indicator pattern or isolated submission."
            )

        # Point 3: Threat Intelligence / Benchmark Reports
        if threat_reports:
            rep_titles = [f"'{r.get('title')}' ({r.get('source')})" for r in threat_reports[:2]]
            explanation_paragraphs.append(
                f"📋 THREAT ADVISORY LINK: The knowledge graph traced 1-to-2 hop relationships linking "
                f"these indicators to {len(threat_reports)} threat intelligence record(s): {', '.join(rep_titles)}. "
                f"Verification Status: {threat_reports[0].get('verification_status', 'REPORTED')}."
            )

        # Point 4: Claimed Organization Mismatch
        if orgs:
            claimed_name = orgs[0]
            if domains:
                explanation_paragraphs.append(
                    f"⚠️ IMPERSONATION VECTOR: Message claims affiliation with '{claimed_name}', but directs traffic "
                    f"to unofficial domain '{domains[0]}'. Legitimate '{claimed_name}' communications do not route "
                    f"credential authentication through third-party or generic TLDs."
                )

        full_narrative = "\n\n".join(explanation_paragraphs)

        return {
            "investigated_message_id": target_id,
            "status": "investigated",
            "detector_assessment": {
                "risk_score": baseline_score,
                "risk_level": baseline_level,
                "category": analysis.get("category", "NORMAL"),
                "summary": analysis.get("summary", "")
            },
            "graph_summary": {
                "shared_indicators_count": shared_entity_count,
                "related_messages_count": related_count,
                "threat_reports_count": len(threat_reports),
                "is_active_campaign": related_count >= 1 or len(threat_reports) >= 1
            },
            "extracted_indicators": indicators,
            "connected_entities": {
                "domains": domains,
                "urls": extracted.get("urls", []),
                "phones": phones,
                "organizations": orgs
            },
            "shared_indicators": shared_indicators,
            "related_messages": list(unique_related_messages.values()),
            "threat_reports": threat_reports,
            "visual_network": network,
            "agent_explanation": full_narrative,
            "limitations_and_uncertainty": (
                "CRITICAL INVESTIGATIVE LIMITATION: A shared domain, IP address, or phone number "
                "is an investigative lead for pattern clustering, not definitive proof of fraud. "
                "Shared cloud hosting, URL shorteners, or multi-tenant gateways may exhibit benign "
                "indicator sharing. Always verify critical alerts through official out-of-band channels."
            ),
            "recommended_actions": analysis.get("recommendations", {
                "donts": ["Do not click links", "Never share credentials or OTPs"],
                "dos": ["Verify independently with the official institution"]
            })
        }


investigation_agent = InvestigationAgent()
