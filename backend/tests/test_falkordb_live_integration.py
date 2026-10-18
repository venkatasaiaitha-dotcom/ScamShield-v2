"""
ScamShield Graph — Real FalkorDB Live Integration Test Suite
Separated live integration tests that execute against an actual FalkorDB instance on port 6379.
Automatically skips with informative message if the live FalkorDB instance is not running.
"""

import pytest
from backend.services.graph_service import graph_service
from backend.scripts.seed_graph import seed_graph, SYNTHETIC_CAMPAIGNS
from backend.agents.investigation_agent import investigation_agent

is_falkor_online, falkor_reason = graph_service.check_connection()

@pytest.mark.skipif(
    not is_falkor_online,
    reason=f"FalkorDB instance offline on {graph_service.host}:{graph_service.port}. Start via Docker to run live integration tests."
)
class TestFalkorDBLiveIntegration:
    """Integration test suite executed only when real FalkorDB instance is reachable."""

    def test_live_connection_and_schema_init(self):
        """Verifies schema indices creation on live FalkorDB."""
        init_res = graph_service.init_schema()
        assert init_res["status"] == "success"
        assert init_res["indices_configured"] >= 5

    def test_live_idempotent_seeding(self):
        """Verifies seed script populates campaigns and running twice does not duplicate nodes."""
        res1 = seed_graph()
        assert res1["status"] == "success"
        assert res1["campaigns_seeded"] == len(SYNTHETIC_CAMPAIGNS)

        stats1 = graph_service.get_graph_stats()
        msg_count_1 = stats1["counts"].get("Message", 0)

        # Re-run seed (idempotency verification)
        res2 = seed_graph()
        assert res2["status"] == "success"

        stats2 = graph_service.get_graph_stats()
        msg_count_2 = stats2["counts"].get("Message", 0)

        # Assert no duplicate nodes created
        assert msg_count_1 == msg_count_2

    def test_live_cypher_investigation(self):
        """Verifies real Cypher queries find shared indicators and trace relationships."""
        shared = graph_service.find_shared_indicators("DRILL_FAKE_KYC")
        assert isinstance(shared, list)
        assert len(shared) > 0
        # Check that related message was matched
        assert any("sbi-kyc-verify-portal.in" in s.get("indicator_value", "") for s in shared)

        evidence = graph_service.trace_connected_evidence("DRILL_FAKE_KYC")
        assert evidence["found"] is True
        assert len(evidence["threat_reports"]) > 0
        assert len(evidence["extracted_entities"]["domains"]) > 0
