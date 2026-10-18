"""
ScamShield Graph — FalkorDB Knowledge Graph Service
Integrates FalkorDB Python client to model, store, and query connected scam intelligence.
Supports parameterized Cypher queries, idempotent schema creation, shared-indicator tracking,
and multi-hop relationship investigation.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from falkordb import FalkorDB

from ..config import (
    FALKORDB_HOST,
    FALKORDB_PORT,
    FALKORDB_PASSWORD,
    FALKORDB_GRAPH,
    FALKORDB_SSL,
    FALKORDB_TIMEOUT_MS
)

logger = logging.getLogger("scamshield.graph")


class FalkorDBUnavailableError(Exception):
    """Raised when FalkorDB graph database cannot be reached."""
    pass


class GraphService:
    def __init__(self):
        self.host = FALKORDB_HOST
        self.port = FALKORDB_PORT
        self.password = FALKORDB_PASSWORD
        self.graph_name = FALKORDB_GRAPH
        self.ssl = FALKORDB_SSL
        self.timeout_ms = FALKORDB_TIMEOUT_MS
        self._client: Optional[FalkorDB] = None
        self._graph = None

    def _get_client(self) -> FalkorDB:
        """Returns or instantiates the FalkorDB client with strict timeouts."""
        if self._client is None:
            self._client = FalkorDB(
                host=self.host,
                port=self.port,
                password=self.password,
                ssl=self.ssl,
                socket_connect_timeout=2.5,
                socket_timeout=3.5,
            )
        return self._client

    def get_graph(self):
        """Returns the selected FalkorDB graph instance."""
        client = self._get_client()
        return client.select_graph(self.graph_name)

    def check_connection(self) -> Tuple[bool, str]:
        """
        Tests connection to FalkorDB.
        Returns (is_connected, message).
        """
        try:
            graph = self.get_graph()
            # Perform a lightweight ping query
            res = graph.query("RETURN 1 AS ping", timeout=self.timeout_ms)
            if res is not None:
                return True, f"Connected to FalkorDB at {self.host}:{self.port} (Graph: '{self.graph_name}')"
            return False, f"FalkorDB returned empty response at {self.host}:{self.port}"
        except Exception as e:
            return False, (
                f"FalkorDB service unreachable at {self.host}:{self.port}. "
                f"Ensure FalkorDB is running via 'docker run -p 6379:6379 -d falkordb/falkordb:latest' "
                f"or check FALKORDB_HOST/PORT in .env. Details: {str(e)}"
            )

    def init_schema(self) -> Dict[str, Any]:
        """
        Creates graph indices idempotently for fast Cypher traversals.
        """
        is_ok, msg = self.check_connection()
        if not is_ok:
            raise FalkorDBUnavailableError(msg)

        graph = self.get_graph()
        index_queries = [
            "CREATE INDEX FOR (m:Message) ON (m.id)",
            "CREATE INDEX FOR (d:Domain) ON (d.name)",
            "CREATE INDEX FOR (u:URL) ON (u.url)",
            "CREATE INDEX FOR (p:Phone) ON (p.number)",
            "CREATE INDEX FOR (o:Organization) ON (o.name)",
            "CREATE INDEX FOR (i:Indicator) ON (i.id)",
            "CREATE INDEX FOR (r:Report) ON (r.id)"
        ]

        created = []
        for q in index_queries:
            try:
                graph.query(q)
                created.append(q)
            except Exception as ex:
                # FalkorDB raises if index already exists; we ignore duplicate index creation
                logger.debug(f"Index creation notice: {ex}")

        return {
            "status": "success",
            "graph": self.graph_name,
            "indices_configured": len(index_queries)
        }

    # =========================================================================
    # INGESTION & ENTITY EXTRACTION
    # =========================================================================

    def ingest_analysis_to_graph(self, analysis: Dict[str, Any], full_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Takes a ScamShield analysis result and merges its nodes and relationships
        into the FalkorDB knowledge graph.
        """
        is_ok, err_msg = self.check_connection()
        if not is_ok:
            logger.warning(f"Skipping graph ingestion (FalkorDB offline): {err_msg}")
            return {"status": "skipped", "reason": "falkordb_offline"}

        graph = self.get_graph()

        msg_id = analysis.get("id") or analysis.get("message_id")
        sender = analysis.get("sender", "Unknown")
        content_preview = analysis.get("content_preview") or (full_content[:120] if full_content else "No preview")
        risk_score = int(analysis.get("risk_score", 0))
        risk_level = str(analysis.get("risk_level", "LOW"))
        category = str(analysis.get("category", "NORMAL"))
        timestamp = str(analysis.get("timestamp", ""))
        is_synthetic = bool(analysis.get("is_synthetic", False) or analysis.get("source") == "DEMO")

        # 1. Merge Message Node
        graph.query(
            """
            MERGE (m:Message {id: $msg_id})
            SET m.sender = $sender,
                m.content_preview = $content_preview,
                m.risk_score = $risk_score,
                m.risk_level = $risk_level,
                m.category = $category,
                m.timestamp = $timestamp,
                m.is_synthetic = $is_synthetic
            """,
            {
                "msg_id": msg_id,
                "sender": sender,
                "content_preview": content_preview,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "category": category,
                "timestamp": timestamp,
                "is_synthetic": is_synthetic
            }
        )

        # 2. Extract and link URLs and Domains
        urls_detected = analysis.get("urls_detected", [])
        for item in urls_detected:
            url_str = item.get("url")
            domain_str = item.get("domain") or self._extract_domain(url_str)
            if not url_str or not domain_str:
                continue

            is_ip = bool(item.get("is_ip_address", False))
            is_short = bool(item.get("is_shortener", False))
            is_lookalike = bool(item.get("is_lookalike", False))
            url_risk = int(item.get("risk_contribution", 0))

            graph.query(
                """
                MATCH (m:Message {id: $msg_id})
                MERGE (u:URL {url: $url})
                SET u.is_ip = $is_ip,
                    u.is_shortener = $is_short,
                    u.risk_score = $url_risk
                MERGE (d:Domain {name: $domain})
                SET d.is_typosquat = $is_lookalike
                MERGE (m)-[:CONTAINS]->(u)
                MERGE (u)-[:HOSTED_ON]->(d)
                """,
                {
                    "msg_id": msg_id,
                    "url": url_str,
                    "is_ip": is_ip,
                    "is_short": is_short,
                    "url_risk": url_risk,
                    "domain": domain_str,
                    "is_lookalike": is_lookalike
                }
            )

        # 3. Extract and link Phone numbers
        phone_match = self._extract_phone(sender, full_content or content_preview)
        if phone_match:
            graph.query(
                """
                MATCH (m:Message {id: $msg_id})
                MERGE (p:Phone {number: $phone})
                MERGE (m)-[:MENTIONS]->(p)
                """,
                {"msg_id": msg_id, "phone": phone_match}
            )

        # 4. Extract and link Claimed Organization
        claimed_org = self._extract_claimed_org(sender, full_content or content_preview, category)
        if claimed_org:
            graph.query(
                """
                MATCH (m:Message {id: $msg_id})
                MERGE (o:Organization {name: $org_name})
                SET o.category = $org_cat
                MERGE (m)-[:CLAIMS_TO_REPRESENT]->(o)
                """,
                {"msg_id": msg_id, "org_name": claimed_org["name"], "org_cat": claimed_org["category"]}
            )

        # 5. Extract and link Indicators from Reasons
        reasons = analysis.get("reasons", [])
        for idx, r in enumerate(reasons):
            title = r.get("title", "") if isinstance(r, dict) else str(r)
            desc = r.get("description", "") if isinstance(r, dict) else ""
            sev = r.get("severity", "MEDIUM") if isinstance(r, dict) else "MEDIUM"
            ind_id = re.sub(r'[^A-Z0-9_]', '_', title.upper())[:40] or f"IND_{idx}"

            graph.query(
                """
                MATCH (m:Message {id: $msg_id})
                MERGE (i:Indicator {id: $ind_id})
                SET i.name = $name,
                    i.description = $desc,
                    i.severity = $sev
                MERGE (m)-[:HAS_INDICATOR]->(i)
                """,
                {
                    "msg_id": msg_id,
                    "ind_id": ind_id,
                    "name": title,
                    "desc": desc,
                    "sev": sev
                }
            )

        return {"status": "success", "message_id": msg_id}

    # =========================================================================
    # PHASE 4: MEANINGFUL GRAPH QUERIES
    # =========================================================================

    def find_shared_indicators(self, message_id: str, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Investigation A: Shared indicators.
        Given a message ID, finds other messages that share a domain, phone number,
        or indicator in the knowledge graph.
        """
        is_ok, err_msg = self.check_connection()
        if not is_ok:
            raise FalkorDBUnavailableError(err_msg)

        graph = self.get_graph()

        cypher = """
        MATCH (m:Message {id: $msg_id})-[r1:CONTAINS|MENTIONS|HAS_INDICATOR]->(shared)<-[r2:CONTAINS|MENTIONS|HAS_INDICATOR]-(other:Message)
        WHERE other.id <> m.id
        RETURN
            coalesce(shared.name, shared.url, shared.number, shared.id) AS indicator_val,
            labels(shared) AS indicator_labels,
            type(r1) AS relationship,
            other.id AS other_id,
            other.sender AS other_sender,
            other.content_preview AS other_preview,
            other.risk_score AS other_risk_score,
            other.category AS other_category,
            other.timestamp AS other_timestamp,
            other.is_synthetic AS other_is_synthetic
        LIMIT $limit
        """

        result = graph.query(cypher, {"msg_id": message_id, "limit": limit})
        shared_list = []
        if result and result.result_set:
            for row in result.result_set:
                shared_list.append({
                    "indicator_value": row[0],
                    "indicator_type": row[1][0] if (row[1] and len(row[1]) > 0) else "Entity",
                    "relationship": row[2],
                    "related_message": {
                        "id": row[3],
                        "sender": row[4],
                        "preview": row[5],
                        "risk_score": row[6],
                        "category": row[7],
                        "timestamp": row[8],
                        "is_synthetic": bool(row[9])
                    }
                })
        return shared_list

    def trace_connected_evidence(self, message_id: str, max_depth: int = 2) -> Dict[str, Any]:
        """
        Investigation B: Connected evidence & threat reports.
        Traces relationships between the submitted message, its indicators,
        and available threat intelligence or benchmark reports.
        """
        is_ok, err_msg = self.check_connection()
        if not is_ok:
            raise FalkorDBUnavailableError(err_msg)

        graph = self.get_graph()

        # Query direct entities and connected reports
        cypher = """
        MATCH (m:Message {id: $msg_id})
        OPTIONAL MATCH (m)-[:CONTAINS]->(u:URL)-[:HOSTED_ON]->(d:Domain)
        OPTIONAL MATCH (m)-[:MENTIONS]->(p:Phone)
        OPTIONAL MATCH (m)-[:CLAIMS_TO_REPRESENT]->(o:Organization)
        OPTIONAL MATCH (m)-[:HAS_INDICATOR]->(i:Indicator)
        OPTIONAL MATCH (d)-[:ASSOCIATED_WITH_REPORT]->(dr:Report)
        OPTIONAL MATCH (p)-[:ASSOCIATED_WITH_REPORT]->(pr:Report)
        OPTIONAL MATCH (i)-[:RELATED_TO]->(ir:Report)
        RETURN
            m,
            collect(DISTINCT u.url) AS urls,
            collect(DISTINCT d.name) AS domains,
            collect(DISTINCT p.number) AS phones,
            collect(DISTINCT o.name) AS organizations,
            collect(DISTINCT {id: i.id, name: i.name, severity: i.severity}) AS indicators,
            collect(DISTINCT dr) + collect(DISTINCT pr) + collect(DISTINCT ir) AS raw_reports
        """
        res = graph.query(cypher, {"msg_id": message_id})
        if not res or not res.result_set or res.result_set[0][0] is None:
            return {"found": False, "message_id": message_id}

        row = res.result_set[0]
        msg_node = row[0]
        urls = [u for u in row[1] if u]
        domains = [d for d in row[2] if d]
        phones = [p for p in row[3] if p]
        organizations = [o for o in row[4] if o]
        indicators = [ind for ind in row[5] if ind and ind.get("name")]

        reports_raw = row[6]
        reports = []
        seen_report_ids = set()
        for r in reports_raw:
            if r is not None and hasattr(r, "properties"):
                props = r.properties
                rid = props.get("id")
                if rid and rid not in seen_report_ids:
                    seen_report_ids.add(rid)
                    reports.append({
                        "id": rid,
                        "title": props.get("title", "Threat Report"),
                        "source": props.get("source", "Synthetic Benchmark"),
                        "verification_status": props.get("verification_status", "UNVERIFIED_REPORT"),
                        "summary": props.get("summary", ""),
                        "severity": props.get("severity", "HIGH"),
                        "date": props.get("date", "")
                    })

        # Query 2: Fetch visual graph nodes and edges for UI rendering
        graph_network = self._build_graph_network(message_id)

        return {
            "found": True,
            "message_id": message_id,
            "message_properties": msg_node.properties if hasattr(msg_node, "properties") else {},
            "extracted_entities": {
                "urls": urls,
                "domains": domains,
                "phones": phones,
                "organizations": organizations,
                "indicators": indicators
            },
            "threat_reports": reports,
            "network": graph_network
        }

    def _build_graph_network(self, message_id: str) -> Dict[str, Any]:
        """
        Constructs a serializable nodes/edges network graph centered around message_id.
        """
        graph = self.get_graph()
        cypher = """
        MATCH (m:Message {id: $msg_id})-[r]->(target)
        RETURN 'Message' AS src_type, m.id AS src_id, coalesce(m.sender, m.id) AS src_label,
               type(r) AS rel,
               labels(target)[0] AS target_type,
               coalesce(target.name, target.url, target.number, target.id) AS target_label,
               coalesce(target.id, target.name, target.url, target.number) AS target_id
        UNION
        MATCH (m:Message {id: $msg_id})-[]->(mid)-[r2]->(leaf)
        RETURN labels(mid)[0] AS src_type,
               coalesce(mid.name, mid.url, mid.number, mid.id) AS src_id,
               coalesce(mid.name, mid.url, mid.number, mid.id) AS src_label,
               type(r2) AS rel,
               labels(leaf)[0] AS target_type,
               coalesce(leaf.title, leaf.name, leaf.id) AS target_label,
               coalesce(leaf.id, leaf.name) AS target_id
        LIMIT 40
        """
        nodes_dict = {}
        edges_list = []

        try:
            res = graph.query(cypher, {"msg_id": message_id})
            if res and res.result_set:
                for row in res.result_set:
                    src_type, src_id, src_label, rel, target_type, target_label, target_id = row

                    if src_id not in nodes_dict:
                        nodes_dict[src_id] = {
                            "id": str(src_id),
                            "label": str(src_label)[:25],
                            "type": src_type
                        }
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": str(target_id),
                            "label": str(target_label)[:25],
                            "type": target_type
                        }
                    edges_list.append({
                        "source": str(src_id),
                        "target": str(target_id),
                        "label": rel
                    })
        except Exception as e:
            logger.debug(f"Graph network visual extraction note: {e}")

        return {
            "nodes": list(nodes_dict.values()),
            "edges": edges_list
        }

    def get_graph_stats(self) -> Dict[str, Any]:
        """Returns node and relationship counts across the knowledge graph."""
        is_ok, err = self.check_connection()
        if not is_ok:
            return {"connected": False, "error": err}

        graph = self.get_graph()
        stats = {"connected": True, "graph": self.graph_name, "counts": {}}
        labels = ["Message", "Domain", "URL", "Phone", "Organization", "Indicator", "Report"]

        for lbl in labels:
            try:
                res = graph.query(f"MATCH (n:{lbl}) RETURN count(n) AS c")
                stats["counts"][lbl] = res.result_set[0][0] if res and res.result_set else 0
            except Exception:
                stats["counts"][lbl] = 0

        try:
            rel_res = graph.query("MATCH ()-[r]->() RETURN count(r) AS c")
            stats["total_relationships"] = rel_res.result_set[0][0] if rel_res and rel_res.result_set else 0
        except Exception:
            stats["total_relationships"] = 0

        return stats

    # =========================================================================
    # EXTRACTION UTILITIES
    # =========================================================================

    def _extract_domain(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        match = re.search(r"https?://([^/:\s]+)", url)
        if match:
            return match.group(1).lower()
        return None

    def _extract_phone(self, sender: str, text: str) -> Optional[str]:
        combined = f"{sender} {text}"
        # Matches formats like +91-98765-43210, +91 9876543210, (555) 123-4567, 9876543210
        match = re.search(r"(\+?\d{1,4}[-.\s]?)?\(?\d{2,5}\)?[-.\s]?\d{3,5}([-.\s]?\d{3,5})?", combined)
        if match:
            clean = match.group(0).strip()
            digits = re.sub(r'\D', '', clean)
            if len(digits) >= 10:
                return clean
        return None

    def _extract_claimed_org(self, sender: str, text: str, category: str) -> Optional[Dict[str, str]]:
        haystack = f"{sender} {text}".lower()
        known_orgs = [
            ("sbi", "State Bank of India", "Banking"),
            ("hdfc", "HDFC Bank", "Banking"),
            ("icici", "ICICI Bank", "Banking"),
            ("axis", "Axis Bank", "Banking"),
            ("bescom", "BESCOM Power Utility", "Utility"),
            ("indiapost", "India Post Delivery", "Logistics"),
            ("amazon", "Amazon India", "E-Commerce"),
            ("netflix", "Netflix Support", "Entertainment"),
            ("telegram", "Telegram Jobs", "Social Media"),
            ("google", "Google Security", "Tech")
        ]
        for key, name, cat in known_orgs:
            if key in haystack:
                return {"name": name, "category": cat}
        return None


graph_service = GraphService()
