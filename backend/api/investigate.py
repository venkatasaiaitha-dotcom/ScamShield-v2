"""
ScamShield Graph — Investigation API Routes
Provides endpoints for health checks, graph-powered investigation,
and graph metrics.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, status
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from ..agents.investigation_agent import investigation_agent
from ..services.graph_service import graph_service, FalkorDBUnavailableError
from ..database import get_analysis_by_id
from ..security.deps import get_optional_user, get_current_user
from ..security.rate_limiter import rate_limit
from ..scripts.seed_graph import seed_graph

router = APIRouter(prefix="/api", tags=["Graph Investigation"])


class InvestigateRequest(BaseModel):
    message_id: Optional[str] = Field(None, max_length=120)
    content: Optional[str] = Field(None, max_length=100000)
    sender: Optional[str] = Field("Manual Inspection", max_length=320)


@router.get("/health")
async def health_check():
    """
    Health check endpoint reporting application and graph database status.
    Returns status of FastAPI backend, SQLite persistence, and FalkorDB graph connectivity.
    """
    falkor_ok, falkor_msg = graph_service.check_connection()

    return {
        "status": "healthy" if falkor_ok else "degraded",
        "service": "ScamShield Graph Backend",
        "version": "2.0.0-graph",
        "components": {
            "fastapi": "online",
            "sqlite": "online",
            "falkordb": {
                "status": "connected" if falkor_ok else "unreachable",
                "host": graph_service.host,
                "port": graph_service.port,
                "graph": graph_service.graph_name,
                "message": falkor_msg
            }
        }
    }


@router.post(
    "/investigate",
    dependencies=[Depends(rate_limit(max_requests=40, window_seconds=60, group="investigate"))]
)
async def investigate_message_endpoint(
    req: InvestigateRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    Runs graph investigation on an incoming or historic message.
    Queries FalkorDB for shared indicators, related messages, and threat advisories.
    """
    if not req.message_id and not req.content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'message_id' or 'content' must be supplied."
        )

    existing_analysis = None
    if req.message_id:
        existing_analysis = get_analysis_by_id(req.message_id)

    try:
        result = await investigation_agent.investigate_message(
            message_id=req.message_id,
            content=req.content,
            sender=req.sender,
            existing_analysis=existing_analysis
        )
        return result
    except FalkorDBUnavailableError as ex:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"FalkorDB service unavailable: {str(ex)}"
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {str(ex)}"
        )


@router.get("/investigate/{message_id}")
async def get_investigation_by_id(
    message_id: str,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    Retrieves connected evidence investigation for a known message ID.
    """
    clean_id = message_id.strip()
    if not clean_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message ID cannot be empty.")

    existing_analysis = get_analysis_by_id(clean_id)

    try:
        result = await investigation_agent.investigate_message(
            message_id=clean_id,
            existing_analysis=existing_analysis
        )
        return result
    except FalkorDBUnavailableError as ex:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"FalkorDB service unavailable: {str(ex)}"
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {str(ex)}"
        )


@router.get("/graph/stats")
async def get_graph_statistics():
    """
    Returns graph database statistics, including node counts by label and total relationships.
    """
    return graph_service.get_graph_stats()


@router.post("/graph/seed")
async def seed_graph_endpoint(current_user: dict = Depends(get_current_user)):
    """
    Triggers idempotent seeding of synthetic demonstration campaigns into FalkorDB.
    Protected with authentication.
    """
    try:
        res = seed_graph()
        return res
    except FalkorDBUnavailableError as ex:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"FalkorDB service unavailable: {str(ex)}"
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Seeding failed: {str(ex)}"
        )
