@echo off
title ScamShield Graph — Connected Scam Investigation Agent
echo ==============================================================================
echo    ScamShield Graph -- Explainable Scam Investigation Agent
echo    Graph Hacks 2026 Track 1: Agents That Act on Connected Data (FalkorDB)
echo ==============================================================================
echo.
echo [1/3] Setting working directory...
cd /d "%~dp0"
echo.
echo [2/3] FalkorDB Knowledge Graph note:
echo       To launch local FalkorDB via Docker (optional):
echo       docker run -p 6379:6379 -d falkordb/falkordb:latest
echo       or: docker compose up -d
echo.
echo [3/3] Starting ScamShield Graph Application Server...
echo ==============================================================================
echo  Localhost URL: http://127.0.0.1:8000
echo  API Documentation: http://127.0.0.1:8000/docs
echo ==============================================================================
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause
