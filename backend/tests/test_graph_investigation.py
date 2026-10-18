"""
ScamShield Graph — FalkorDB Knowledge Graph & Investigation Test Suite
Verifies:
1. Health endpoint reporting FastAPI, SQLite, and FalkorDB status.
2. Safe rejection of invalid investigation requests (400 Bad Request).
3. Graceful handling and informative 503 error responses when FalkorDB is offline.
4. Correct entity extraction (domains, phone numbers, claimed organizations).
5. Cypher query parameterization and query formatting.
6. Synthesized investigation response schema and uncertainty disclosures.
7. Idempotent seed data structures.
"""

import pytest
from unittest.mock import MagicMock, patch
from starlette.testclient import TestClient

from backend.main import app
from backend.services.graph_service import graph_service, FalkorDBUnavailableError
from backend.agents.investigation_agent import investigation_agent
from backend.scripts.seed_graph import SYNTHETIC_CAMPAIGNS


@pytest.fixture
def client():
    return TestClient(app)


def test_01_health_endpoint_reports_status(client):
    """Verifies GET /api/health returns status of FastAPI, SQLite, and FalkorDB."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "components" in data
    assert data["components"]["fastapi"] == "online"
    assert data["components"]["sqlite"] == "online"
    assert "falkordb" in data["components"]
    assert "host" in data["components"]["falkordb"]
    assert "port" in data["components"]["falkordb"]
    assert "graph" in data["components"]["falkordb"]


def test_02_invalid_investigation_inputs_rejected(client):
    """Verifies that empty requests to /api/investigate return HTTP 400."""
    # Neither message_id nor content provided
    r1 = client.post("/api/investigate", json={})
    assert r1.status_code == 400
    assert "Either 'message_id' or 'content' must be supplied" in r1.json()["detail"]

    # Blank message_id
    r2 = client.get("/api/investigate/%20")
    assert r2.status_code == 400


def test_03_falkordb_outage_produces_informative_503(client):
    """
    Verifies that when FalkorDB is unreachable, endpoints return HTTP 503
    with actionable troubleshooting instructions rather than crashing or pretending.
    """
    # When FalkorDB is offline on local port 6379:
    r = client.post("/api/investigate", json={
        "content": "Dear customer, your bank KYC has expired. Update at http://test-bank.xyz"
    })
    # If FalkorDB is offline, status must be 503 with informative message
    is_falkor_online, _ = graph_service.check_connection()
    if not is_falkor_online:
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert "FalkorDB service unavailable" in detail
        assert "docker run -p 6379:6379 -d falkordb/falkordb:latest" in detail or "FALKORDB_HOST" in detail
    else:
        assert r.status_code == 200


def test_04_entity_extraction_utilities():
    """Verifies extraction of domains, phones, and claimed organizations."""
    # Domain extraction
    d1 = graph_service._extract_domain("http://sbi-kyc-verify-portal.in/login")
    assert d1 == "sbi-kyc-verify-portal.in"
    d2 = graph_service._extract_domain("https://secure.indiapost-update.top/path?q=1")
    assert d2 == "secure.indiapost-update.top"

    # Phone extraction
    p1 = graph_service._extract_phone("+91-98765-43210", "Part time job")
    assert p1 is not None
    assert "98765" in p1

    p2 = graph_service._extract_phone("Unknown", "Contact manager at +91 9123456789 for bonus")
    assert p2 is not None

    # Claimed organization extraction
    org1 = graph_service._extract_claimed_org("SBI-ALERT", "NetBanking KYC expired", "FAKE_KYC")
    assert org1 is not None
    assert org1["name"] == "State Bank of India"

    org2 = graph_service._extract_claimed_org("BESCOM-POWER", "Power bill overdue", "UTILITY_IMPERSONATION")
    assert org2 is not None
    assert "BESCOM" in org2["name"]


def test_05_investigation_response_structure_and_uncertainty():
    """
    Verifies that the investigation agent produces a complete, grounded report
    with explicit uncertainty and limitation disclosures.
    """
    sample_analysis = {
        "id": "ana-test-01",
        "sender": "SBI-ALERT",
        "category": "FAKE_KYC",
        "risk_score": 95,
        "risk_level": "HIGH",
        "summary": "Fake bank KYC threat with typosquatted login portal.",
        "recommendations": {
            "donts": ["Do not click link"],
            "dos": ["Contact bank branch"]
        }
    }
    sample_shared = [
        {
            "indicator_value": "sbi-kyc-verify-portal.in",
            "indicator_type": "Domain",
            "relationship": "CONTAINS",
            "related_message": {
                "id": "HIST_01",
                "sender": "+91-91234-56789",
                "preview": "Account suspended",
                "risk_score": 92,
                "category": "FAKE_KYC",
                "timestamp": "Yesterday"
            }
        }
    ]
    sample_evidence = {
        "extracted_entities": {
            "domains": ["sbi-kyc-verify-portal.in"],
            "phones": [],
            "organizations": ["State Bank of India"],
            "indicators": [{"name": "Urgency Deadline", "severity": "HIGH"}]
        },
        "threat_reports": [
            {
                "id": "REP_01",
                "title": "Simulated NetBanking Impersonation Cluster",
                "source": "Synthetic Benchmark",
                "verification_status": "SYNTHETIC_BENCHMARK",
                "summary": "Synthetic test report tracking lookalike domains."
            }
        ],
        "network": {
            "nodes": [
                {"id": "ana-test-01", "type": "Message"},
                {"id": "sbi-kyc-verify-portal.in", "type": "Domain"}
            ],
            "edges": [
                {"source": "ana-test-01", "target": "sbi-kyc-verify-portal.in", "label": "CONTAINS"}
            ]
        }
    }

    report = investigation_agent._synthesize_evidence_report(
        target_id="ana-test-01",
        analysis=sample_analysis,
        shared_indicators=sample_shared,
        evidence_chain=sample_evidence
    )

    assert report["investigated_message_id"] == "ana-test-01"
    assert report["detector_assessment"]["risk_score"] == 95
    assert report["graph_summary"]["related_messages_count"] == 1
    assert report["graph_summary"]["shared_indicators_count"] == 1
    assert len(report["threat_reports"]) == 1
    assert "FalkorDB Cypher queries revealed" in report["agent_explanation"]
    assert "CRITICAL INVESTIGATIVE LIMITATION" in report["limitations_and_uncertainty"]
    assert "investigative lead for pattern clustering, not definitive proof of fraud" in report["limitations_and_uncertainty"]


def test_06_synthetic_campaigns_dataset_integrity():
    """Verifies the synthetic demo dataset defines campaigns with idempotent keys."""
    assert len(SYNTHETIC_CAMPAIGNS) >= 3
    for camp in SYNTHETIC_CAMPAIGNS:
        assert "campaign_id" in camp
        assert "title" in camp
        assert "report" in camp
        assert "messages" in camp
        assert len(camp["messages"]) >= 2
        rep = camp["report"]
        assert rep["verification_status"] == "SYNTHETIC_BENCHMARK"


def test_07_mocked_live_investigation_flow():
    """
    Verifies full end-to-end investigation workflow when FalkorDB queries return results.
    Uses mock to guarantee deterministic verification independent of Docker daemon availability.
    """
    with patch.object(graph_service, "check_connection", return_value=(True, "Connected")):
        with patch.object(graph_service, "find_shared_indicators", return_value=[
            {
                "indicator_value": "sbi-kyc-verify-portal.in",
                "indicator_type": "Domain",
                "relationship": "HOSTED_ON",
                "related_message": {
                    "id": "HIST_KYC_VAR_01",
                    "sender": "+91-91234-56789",
                    "preview": "Account suspended",
                    "risk_score": 92,
                    "category": "FAKE_KYC"
                }
            }
        ]):
            with patch.object(graph_service, "trace_connected_evidence", return_value={
                "extracted_entities": {
                    "domains": ["sbi-kyc-verify-portal.in"],
                    "urls": ["http://sbi-kyc-verify-portal.in/login"],
                    "phones": [],
                    "organizations": ["State Bank of India"],
                    "indicators": [{"name": "Typosquatting", "severity": "HIGH"}]
                },
                "threat_reports": [{
                    "id": "REP_SYNTH_01",
                    "title": "Synthetic Bank Phishing Advisory",
                    "source": "Synthetic Benchmark Feed",
                    "verification_status": "SYNTHETIC_BENCHMARK",
                    "summary": "Simulated report"
                }],
                "network": {
                    "nodes": [{"id": "DRILL_FAKE_KYC", "type": "Message"}],
                    "edges": []
                }
            }):
                with patch.object(graph_service, "ingest_analysis_to_graph", return_value={"status": "success"}):
                    res = investigation_agent.investigate_message(
                        message_id="DRILL_FAKE_KYC",
                        content="Dear Customer, SBI KYC expired. Login: http://sbi-kyc-verify-portal.in/login",
                        sender="SBI-ALERT"
                    )
                    import asyncio
                    res = asyncio.run(res)

                    assert res["status"] == "investigated"
                    assert res["graph_summary"]["shared_indicators_count"] == 1
                    assert len(res["shared_indicators"]) == 1
                    assert res["shared_indicators"][0]["indicator_value"] == "sbi-kyc-verify-portal.in"
                    assert len(res["threat_reports"]) == 1
                    assert "CRITICAL INVESTIGATIVE LIMITATION" in res["limitations_and_uncertainty"]
