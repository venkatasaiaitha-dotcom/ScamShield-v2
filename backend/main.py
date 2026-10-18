import os
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import ALLOWED_ORIGINS
from .database import init_db, get_stats
from .database.connection import get_user_by_id
from .services.notification_service import notification_service
from .security.headers import SecurityHeadersMiddleware, StructuredLoggingMiddleware
from .security.tokens import verify_token
from .api import (
    auth_router,
    security_router,
    agent_router,
    messages_router,
    alerts_router,
    history_router,
    sources_router,
    settings_router,
    gmail_router,
    community_router,
    investigate_router
)
from .services.graph_service import graph_service

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize SQLite database and bootstrap default accounts
    init_db()
    # Check FalkorDB graph connection
    is_ok, msg = graph_service.check_connection()
    if is_ok:
        try:
            graph_service.init_schema()
        except Exception:
            pass
    yield
    # Shutdown

app = FastAPI(
    title="ScamShield Graph — AI Cyber Defense Agent",
    description="Enterprise-Grade AI Scam Detection & FalkorDB Connected-Evidence Investigation Agent API",
    version="2.0.0-graph",
    lifespan=lifespan
)

# Apply Security Headers and Request Logging Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(StructuredLoggingMiddleware)

# Enable Hardened CORS strictly restricted to trusted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth_router)
app.include_router(security_router)
app.include_router(agent_router)
app.include_router(messages_router)
app.include_router(alerts_router)
app.include_router(history_router)
app.include_router(sources_router)
app.include_router(settings_router)
app.include_router(gmail_router)
app.include_router(community_router)
app.include_router(investigate_router)

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    Part 7: Authenticated WebSocket endpoint with per-user connection isolation.
    Rejects unauthorized connections with 1008 Policy Violation.
    """
    # Accept connection first to negotiate handshake or check credentials
    auth_token = token or websocket.cookies.get("access_token")
    if not auth_token:
        # Check query string directly if needed
        params = dict(websocket.query_params)
        auth_token = params.get("token")

    if not auth_token:
        # Reject unauthorized connection
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
        return

    payload = verify_token(auth_token, expected_type="access")
    if not payload or "sub" not in payload:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token")
        return

    user_id = payload["sub"]
    user = get_user_by_id(user_id)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User account not found")
        return

    await notification_service.connect(websocket, user_id=user_id)
    try:
        # Send initial sync payload isolated to this user
        stats = get_stats(user_id=user_id)
        await websocket.send_json({
            "event": "INITIAL_SYNC",
            "data": {
                "status": "connected",
                "user": {"email": user["email"], "role": user["role"]},
                "stats": stats
            }
        })
        while True:
            # Keep connection alive, listen for client heartbeats
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        notification_service.disconnect(websocket, user_id=user_id)
    except Exception:
        notification_service.disconnect(websocket, user_id=user_id)

# Mount compiled frontend static files if present
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Allow API routes and Docs to proceed with 404 if not found in routers
        if (
            full_path.startswith("api")
            or full_path.startswith("docs")
            or full_path.startswith("openapi.json")
            or full_path.startswith("ws")
        ):
            raise HTTPException(status_code=404, detail="Not Found")
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(
            os.path.join(frontend_dist, "index.html"),
            headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
        )
else:
    @app.get("/")
    async def root():
        return {
            "service": "ScamShield Agent Backend",
            "tagline": "Enterprise-Grade AI-Powered Proactive Scam Protection",
            "status": "online",
            "docs_url": "/docs"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
