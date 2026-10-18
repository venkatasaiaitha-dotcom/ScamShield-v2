from fastapi import APIRouter, Depends, Query
from typing import Dict, Any, Optional

from ..models.schemas import AgentStatusResponse
from ..agents.scamshield_agent import scamshield_agent
from ..security.deps import get_current_user

router = APIRouter(prefix="/api/agent", tags=["Agent"])

@router.get("/status", response_model=AgentStatusResponse)
@router.get("/stats", response_model=AgentStatusResponse)
async def get_agent_status(
    date_range: str = Query("all", pattern="^(today|7days|30days|all)$"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Returns real protection status and date-filtered statistics for the authenticated user."""
    return scamshield_agent.get_status(user_id=current_user["id"], date_range=date_range)

@router.post("/start")
async def start_protection(current_user: Dict[str, Any] = Depends(get_current_user)):
    scamshield_agent.set_protection_status(current_user["id"], True)
    return {
        "status": "success",
        "protection_active": True,
        "message": "Protection Active - Monitoring connected sources"
    }

@router.post("/pause")
async def pause_protection(current_user: Dict[str, Any] = Depends(get_current_user)):
    scamshield_agent.set_protection_status(current_user["id"], False)
    return {
        "status": "success",
        "protection_active": False,
        "message": "Protection Paused - Incoming messages will not be automatically analyzed"
    }
