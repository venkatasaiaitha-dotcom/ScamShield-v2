import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..models.schemas import IncomingMessage, MessageAnalysis, AgentStatusResponse
from ..database import (
    get_settings,
    update_settings,
    save_analysis,
    get_stats,
    get_sources,
    increment_source_count,
    record_upi_safety,
    record_attack_chain
)
from ..services.message_ingestion import MessageIngestionService
from ..services.notification_service import notification_service
from ..ml.classifier import classifier
from ..connectors import DemoConnector, SMSConnector, EmailConnector, WebhookConnector

class ScamShieldAgent:
    """
    The Core ScamShield AI Agent:
    Operates proactively to monitor incoming messages across active sources,
    extract features, assess risk, generate explanations, and alert the user.
    Maintains tenant isolation so each user's data remains private.
    """
    def __init__(self):
        self.demo_connector = DemoConnector()
        self.sms_connector = SMSConnector()
        self.email_connector = EmailConnector()
        self.webhook_connector = WebhookConnector()

    def is_protection_active(self, user_id: str) -> bool:
        settings = get_settings(user_id)
        return settings.get("protection_enabled", True)

    def set_protection_status(self, user_id: str, active: bool):
        update_settings(user_id, {"protection_enabled": active})

    def get_status(self, user_id: str, date_range: str = "all") -> AgentStatusResponse:
        settings = get_settings(user_id)
        is_active = settings.get("protection_enabled", True)
        stats = get_stats(user_id, date_range=date_range)
        sources = get_sources(user_id)

        active_sources = [s["name"] for s in sources if s["status"] == "CONNECTED"]

        return AgentStatusResponse(
            protection_active=is_active,
            status_label="Protection Active" if is_active else "Protection Paused",
            monitoring_sources=active_sources,
            messages_checked=stats["messages_checked"],
            threats_detected=stats["threats_detected"],
            high_risk_count=stats["high_risk_count"],
            suspicious_count=stats["suspicious_count"],
            last_active=datetime.now().strftime("%I:%M %p")
        )

    async def process_incoming_message(
        self,
        raw_message: Dict[str, Any],
        user_id: str = "system",
        default_source: str = "DEMO"
    ) -> Dict[str, Any]:
        """
        Main Agent Execution Pipeline:
        RECEIVE -> UNDERSTAND -> ANALYZE -> CLASSIFY -> EXPLAIN -> PERSIST -> ALERT IF NECESSARY
        """
        # 1. Ingest & normalize
        normalized = MessageIngestionService.ingest(raw_message, default_source)
        source_type = normalized["source"]

        # Increment message count for the user's source
        increment_source_count(user_id, source_type)

        settings = get_settings(user_id)
        protection_enabled = settings.get("protection_enabled", True)

        # If protection is paused, do not analyze
        if not protection_enabled:
            return {
                "id": f"ana-paused-{uuid.uuid4().hex[:6]}",
                "message_id": normalized["id"],
                "source": source_type,
                "sender": normalized["sender"],
                "content_preview": normalized["content"][:80] + ("..." if len(normalized["content"]) > 80 else ""),
                "timestamp": normalized["timestamp"],
                "risk_score": 0,
                "risk_level": "LOW",
                "category": "NORMAL",
                "summary": "Protection is currently paused. Message was received without automatic security analysis.",
                "reasons": [{
                    "title": "Monitoring Paused",
                    "description": "Resume protection in dashboard to re-enable automated threat inspection.",
                    "severity": "LOW"
                }],
                "recommendations": {
                    "donts": [],
                    "dos": ["Enable ScamShield protection to analyze incoming messages."]
                },
                "urls_detected": [],
                "technical_details": {"protection_paused": True}
            }

        high_thresh = settings.get("high_risk_threshold", 70)
        susp_thresh = settings.get("suspicious_threshold", 30)
        minimal_metadata = settings.get("privacy_minimal_metadata", True)

        # 2. Hybrid Classification & Deep Analysis
        analysis_result = classifier.process(
            content=normalized["content"],
            sender=normalized["sender"],
            custom_high_thresh=high_thresh,
            custom_susp_thresh=susp_thresh
        )

        analysis_id = f"ana-{uuid.uuid4().hex[:8]}"
        content_preview = normalized["content"][:100] + ("..." if len(normalized["content"]) > 100 else "")

        full_analysis_dict = {
            "id": analysis_id,
            "message_id": normalized["id"],
            "source": source_type,
            "sender": normalized["sender"],
            "content_preview": content_preview,
            "timestamp": normalized["timestamp"],
            "risk_score": analysis_result["risk_score"],
            "risk_level": analysis_result["risk_level"],
            "category": analysis_result["category"],
            "summary": analysis_result["summary"],
            "reasons": analysis_result["reasons"],
            "recommendations": analysis_result["recommendations"],
            "urls_detected": analysis_result["urls_detected"],
            "technical_details": analysis_result["technical_details"],
            "scam_dna": analysis_result.get("scam_dna"),
            "attack_chain": analysis_result.get("attack_chain"),
            "next_moves_forecast": analysis_result.get("next_moves_forecast", []),
            "upi_safety": analysis_result.get("upi_safety"),
            "multilingual": analysis_result.get("multilingual")
        }

        # 3. Save to database with user tenant isolation
        save_analysis(full_analysis_dict, normalized["content"], user_id=user_id, privacy_minimal=minimal_metadata)

        # Record secondary telemetry
        if analysis_result.get("upi_safety"):
            try:
                record_upi_safety(analysis_result["upi_safety"], analysis_id)
            except Exception:
                pass

        if analysis_result.get("attack_chain"):
            try:
                cid = analysis_result.get("scam_dna", {}).get("campaign_id")
                record_attack_chain(user_id, analysis_result["attack_chain"], campaign_id=cid)
            except Exception:
                pass

        # Record into FalkorDB Knowledge Graph (Track 1: Connected Evidence)
        try:
            from ..services.graph_service import graph_service
            graph_service.ingest_analysis_to_graph(full_analysis_dict, full_content=normalized["content"])
        except Exception:
            pass

        # 4. Dispatch live real-time notification to the user's authenticated WebSocket only
        stats = get_stats(user_id)
        await notification_service.dispatch_analysis_event(user_id, full_analysis_dict, stats)

        return full_analysis_dict

scamshield_agent = ScamShieldAgent()
