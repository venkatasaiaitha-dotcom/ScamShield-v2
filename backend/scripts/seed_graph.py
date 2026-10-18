"""
ScamShield Graph — Idempotent Knowledge Graph Seeding Script
Populates FalkorDB with synthetic demonstration scenarios, indicators, and threat intelligence reports.
All queries use MERGE to guarantee idempotency (running multiple times creates NO duplicate nodes or edges).
"""

import sys
import os
import logging
from pathlib import Path
from typing import Dict, Any, List

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.graph_service import graph_service, FalkorDBUnavailableError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scamshield.seed")

# Synthetic demonstration dataset
SYNTHETIC_CAMPAIGNS = [
    {
        "campaign_id": "CAMP_FAKE_KYC_SBI",
        "title": "Simulated NetBanking Credential Harvesting Cluster",
        "primary_domain": "sbi-kyc-verify-portal.in",
        "primary_org": "State Bank of India",
        "report": {
            "id": "REP_SYNTH_KYC_01",
            "title": "Synthetic Threat Advisory: Bank Impersonation & Typosquatting Cluster",
            "source": "Synthetic Threat Intelligence Feed (Hackathon Demo)",
            "verification_status": "SYNTHETIC_BENCHMARK",
            "severity": "HIGH",
            "date": "2026-10-15",
            "summary": "Simulated investigative report tracking fake banking domains mimicking national banks for credential extraction."
        },
        "messages": [
            {
                "id": "DRILL_FAKE_KYC",
                "sender": "SBI-ALERT",
                "preview": "Dear Customer, Your SBI NetBanking KYC has expired today. Your account and card will be deactivated in 12 hours. Update KYC immediately at: http://sbi-kyc-verify-portal.in/login",
                "risk_score": 96,
                "risk_level": "HIGH",
                "category": "FAKE_KYC",
                "timestamp": "2026-10-18 10:14 AM",
                "url": "http://sbi-kyc-verify-portal.in/login",
                "is_lookalike": True,
                "indicators": [
                    {"id": "IND_ARTIFICIAL_URGENCY", "name": "Artificial Urgency Deadline (12h deactivation)", "severity": "HIGH"},
                    {"id": "IND_TYPOSQUAT_BANK", "name": "Typosquatted Banking Domain (.in deceptive path)", "severity": "CRITICAL"},
                    {"id": "IND_CREDENTIAL_THEFT", "name": "Credential Harvesting Login Form", "severity": "HIGH"}
                ]
            },
            {
                "id": "HIST_KYC_VAR_01",
                "sender": "+91-91234-56789",
                "preview": "URGENT: SBI Account suspended due to incomplete KYC submission. Click here to reactivate: http://sbi-kyc-verify-portal.in/update",
                "risk_score": 92,
                "risk_level": "HIGH",
                "category": "FAKE_KYC",
                "timestamp": "2026-10-16 04:30 PM",
                "url": "http://sbi-kyc-verify-portal.in/update",
                "is_lookalike": True,
                "indicators": [
                    {"id": "IND_ARTIFICIAL_URGENCY", "name": "Artificial Urgency Deadline", "severity": "HIGH"},
                    {"id": "IND_TYPOSQUAT_BANK", "name": "Typosquatted Banking Domain", "severity": "CRITICAL"}
                ]
            },
            {
                "id": "HIST_KYC_VAR_02",
                "sender": "SBI-UPDATE",
                "preview": "State Bank alert: Immediate PAN card linking mandatory to prevent card block at http://sbi-kyc-verify-portal.in/pan",
                "risk_score": 88,
                "risk_level": "HIGH",
                "category": "FAKE_KYC",
                "timestamp": "2026-10-17 08:20 AM",
                "url": "http://sbi-kyc-verify-portal.in/pan",
                "is_lookalike": True,
                "indicators": [
                    {"id": "IND_TYPOSQUAT_BANK", "name": "Typosquatted Banking Domain", "severity": "CRITICAL"}
                ]
            }
        ]
    },
    {
        "campaign_id": "CAMP_JOB_TRAP_WHATSAPP",
        "title": "Simulated Part-Time Work Advance Fee Syndicate",
        "primary_phone": "+91-98765-43210",
        "primary_org": "Telegram Jobs",
        "report": {
            "id": "REP_SYNTH_JOB_02",
            "title": "Synthetic Threat Advisory: High-Yield Work-From-Home Advance Fee Trap",
            "source": "Synthetic Threat Intelligence Feed (Hackathon Demo)",
            "verification_status": "SYNTHETIC_BENCHMARK",
            "severity": "HIGH",
            "date": "2026-10-14",
            "summary": "Simulated intelligence note tracking upfront kit fee requests and WhatsApp recruiter numbers."
        },
        "messages": [
            {
                "id": "DRILL_JOB_SCAM",
                "sender": "+91-98765-43210",
                "preview": "Part-Time Work From Home! Rozana ₹3,000 se ₹8,000 kamaye YouTube videos like karke. Joining ke liye turant ₹499 registration kit fee UPI karein quick-work@ybl par.",
                "risk_score": 89,
                "risk_level": "HIGH",
                "category": "JOB_SCAM",
                "timestamp": "2026-10-18 11:45 AM",
                "phone": "+91-98765-43210",
                "indicators": [
                    {"id": "IND_ADVANCE_FEE_KIT", "name": "Upfront Registration Fee Demand", "severity": "HIGH"},
                    {"id": "IND_UNREALISTIC_EARNINGS", "name": "Unrealistic Micro-Task Daily Income", "severity": "HIGH"},
                    {"id": "IND_HINGLISH_CODE_MIX", "name": "Regional Hinglish Social Engineering Bait", "severity": "MEDIUM"}
                ]
            },
            {
                "id": "HIST_JOB_VAR_01",
                "sender": "+91-98765-43210",
                "preview": "Google Review Rating Task: Earn ₹5,000 daily from smartphone. WhatsApp manager at +91-98765-43210 for immediate interview slot.",
                "risk_score": 82,
                "risk_level": "HIGH",
                "category": "JOB_SCAM",
                "timestamp": "2026-10-16 02:15 PM",
                "phone": "+91-98765-43210",
                "indicators": [
                    {"id": "IND_UNREALISTIC_EARNINGS", "name": "Unrealistic Micro-Task Daily Income", "severity": "HIGH"}
                ]
            }
        ]
    },
    {
        "campaign_id": "CAMP_COURIER_INTERCEPT",
        "title": "Simulated Logistics Redirection Phishing",
        "primary_domain": "indiapost-update-address.top",
        "primary_org": "India Post Delivery",
        "report": {
            "id": "REP_SYNTH_COURIER_03",
            "title": "Synthetic Threat Advisory: Delivery Failure Redirection Phishing",
            "source": "Synthetic Threat Intelligence Feed (Hackathon Demo)",
            "verification_status": "SYNTHETIC_BENCHMARK",
            "severity": "HIGH",
            "date": "2026-10-12",
            "summary": "Simulated campaign leveraging parcel delivery failures with abusive .top TLD domains to collect residential addresses and payment cards."
        },
        "messages": [
            {
                "id": "DRILL_COURIER_SCAM",
                "sender": "IndiaPost-Notice",
                "preview": "Your parcel #AMZ-9918 could not be delivered due to incomplete street address. Update address within 24 hours at http://indiapost-update-address.top/redirection or package will be returned.",
                "risk_score": 87,
                "risk_level": "HIGH",
                "category": "DELIVERY_SCAM",
                "timestamp": "2026-10-18 01:20 PM",
                "url": "http://indiapost-update-address.top/redirection",
                "is_lookalike": True,
                "indicators": [
                    {"id": "IND_SUSPICIOUS_TLD_TOP", "name": "High-Abuse Generic TLD (.top)", "severity": "HIGH"},
                    {"id": "IND_IMPERSONATED_POSTAL", "name": "Impersonated Postal Service", "severity": "HIGH"},
                    {"id": "IND_SHORT_FUSE_DEADLINE", "name": "24h Forced Package Return Deadline", "severity": "MEDIUM"}
                ]
            },
            {
                "id": "HIST_COURIER_VAR_01",
                "sender": "PostOffice-Tracking",
                "preview": "Failed delivery notice for package #INP-7741. Re-confirm destination address: http://indiapost-update-address.top/schedule",
                "risk_score": 84,
                "risk_level": "HIGH",
                "category": "DELIVERY_SCAM",
                "timestamp": "2026-10-17 06:10 PM",
                "url": "http://indiapost-update-address.top/schedule",
                "is_lookalike": True,
                "indicators": [
                    {"id": "IND_SUSPICIOUS_TLD_TOP", "name": "High-Abuse Generic TLD (.top)", "severity": "HIGH"},
                    {"id": "IND_IMPERSONATED_POSTAL", "name": "Impersonated Postal Service", "severity": "HIGH"}
                ]
            }
        ]
    }
]


def seed_graph() -> Dict[str, Any]:
    """
    Executes idempotent Cypher MERGE queries to seed the knowledge graph.
    """
    logger.info("Connecting to FalkorDB for schema initialization...")
    is_ok, err = graph_service.check_connection()
    if not is_ok:
        raise FalkorDBUnavailableError(err)

    # 1. Initialize schema and indices
    graph_service.init_schema()
    graph = graph_service.get_graph()

    total_messages = 0
    total_indicators = 0
    total_reports = 0

    for camp in SYNTHETIC_CAMPAIGNS:
        # A. Merge Report Node
        rep = camp["report"]
        graph.query(
            """
            MERGE (r:Report {id: $rid})
            SET r.title = $title,
                r.source = $source,
                r.verification_status = $status,
                r.severity = $sev,
                r.date = $date,
                r.summary = $summary
            """,
            {
                "rid": rep["id"],
                "title": rep["title"],
                "source": rep["source"],
                "status": rep["verification_status"],
                "sev": rep["severity"],
                "date": rep["date"],
                "summary": rep["summary"]
            }
        )
        total_reports += 1

        # B. Merge Organization Node if specified
        org_name = camp.get("primary_org")
        if org_name:
            graph.query(
                """
                MERGE (o:Organization {name: $org_name})
                SET o.category = 'Enterprise / Utility'
                """,
                {"org_name": org_name}
            )

        # C. Merge Domain if specified and link to Report
        domain_name = camp.get("primary_domain")
        if domain_name:
            graph.query(
                """
                MATCH (r:Report {id: $rid})
                MERGE (d:Domain {name: $domain})
                SET d.is_typosquat = true
                MERGE (d)-[:ASSOCIATED_WITH_REPORT]->(r)
                """,
                {"rid": rep["id"], "domain": domain_name}
            )

        # D. Merge Phone if specified and link to Report
        phone_num = camp.get("primary_phone")
        if phone_num:
            graph.query(
                """
                MATCH (r:Report {id: $rid})
                MERGE (p:Phone {number: $phone})
                MERGE (p)-[:ASSOCIATED_WITH_REPORT]->(r)
                """,
                {"rid": rep["id"], "phone": phone_num}
            )

        # E. Process Messages in this synthetic campaign
        for msg in camp["messages"]:
            graph.query(
                """
                MERGE (m:Message {id: $msg_id})
                SET m.sender = $sender,
                    m.content_preview = $preview,
                    m.risk_score = $risk_score,
                    m.risk_level = $risk_level,
                    m.category = $category,
                    m.timestamp = $timestamp,
                    m.is_synthetic = true
                """,
                {
                    "msg_id": msg["id"],
                    "sender": msg["sender"],
                    "preview": msg["preview"],
                    "risk_score": msg["risk_score"],
                    "risk_level": msg["risk_level"],
                    "category": msg["category"],
                    "timestamp": msg["timestamp"]
                }
            )
            total_messages += 1

            # Link Organization
            if org_name:
                graph.query(
                    """
                    MATCH (m:Message {id: $msg_id}), (o:Organization {name: $org_name})
                    MERGE (m)-[:CLAIMS_TO_REPRESENT]->(o)
                    """,
                    {"msg_id": msg["id"], "org_name": org_name}
                )

            # Link URL & Domain
            if msg.get("url"):
                url_str = msg["url"]
                graph.query(
                    """
                    MATCH (m:Message {id: $msg_id}), (d:Domain {name: $domain})
                    MERGE (u:URL {url: $url})
                    SET u.is_ip = false, u.is_shortener = false, u.risk_score = 90
                    MERGE (m)-[:CONTAINS]->(u)
                    MERGE (u)-[:HOSTED_ON]->(d)
                    """,
                    {
                        "msg_id": msg["id"],
                        "url": url_str,
                        "domain": domain_name
                    }
                )

            # Link Phone
            if msg.get("phone"):
                graph.query(
                    """
                    MATCH (m:Message {id: $msg_id}), (p:Phone {number: $phone})
                    MERGE (m)-[:MENTIONS]->(p)
                    """,
                    {"msg_id": msg["id"], "phone": msg["phone"]}
                )

            # Link Indicators
            for ind in msg.get("indicators", []):
                graph.query(
                    """
                    MATCH (m:Message {id: $msg_id}), (r:Report {id: $rid})
                    MERGE (i:Indicator {id: $ind_id})
                    SET i.name = $ind_name, i.severity = $sev
                    MERGE (m)-[:HAS_INDICATOR]->(i)
                    MERGE (i)-[:RELATED_TO]->(r)
                    """,
                    {
                        "msg_id": msg["id"],
                        "rid": rep["id"],
                        "ind_id": ind["id"],
                        "ind_name": ind["name"],
                        "sev": ind.get("severity", "HIGH")
                    }
                )
                total_indicators += 1

    stats = graph_service.get_graph_stats()
    logger.info(f"FalkorDB graph '{graph_service.graph_name}' seeded successfully! Stats: {stats}")
    return {
        "status": "success",
        "message": f"Seeded {total_messages} messages, {total_indicators} indicators, {total_reports} threat reports into '{graph_service.graph_name}'",
        "stats": stats
    }


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    try:
        res = seed_graph()
        print(f"[SUCCESS] {res['message']}")
    except Exception as ex:
        print(f"[ERROR] Seeding failed: {ex}")
        sys.exit(1)
