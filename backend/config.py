import os
import secrets
from typing import List, Optional

# Base Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.getenv("DATABASE_URL", os.path.join(BASE_DIR, "backend", "database", "scamshield.db"))

# Environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
IS_DEV = ENVIRONMENT.lower() in ("development", "dev")

# JWT & Authentication
# If JWT_SECRET is not provided, generate a persistent secure key or fallback to a 32-byte secret
_default_jwt_secret = os.getenv("JWT_SECRET")
if not _default_jwt_secret:
    _key_file = os.path.join(BASE_DIR, "backend", ".jwt_secret")
    if os.path.exists(_key_file):
        with open(_key_file, "r") as f:
            _default_jwt_secret = f.read().strip()
    else:
        _default_jwt_secret = secrets.token_hex(32)
        try:
            with open(_key_file, "w") as f:
                f.write(_default_jwt_secret)
        except Exception:
            pass

JWT_SECRET: str = _default_jwt_secret or secrets.token_hex(32)
JWT_ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# CORS Configuration
_frontend_origin_raw = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000")
ALLOWED_ORIGINS: List[str] = [origin.strip() for origin in _frontend_origin_raw.split(",") if origin.strip()]

# Webhook Secret (HMAC comparison)
SCAMSHIELD_WEBHOOK_SECRET: str = os.getenv("SCAMSHIELD_WEBHOOK_SECRET", "scm_live_sec_token_9921_hackathon")

# Google OAuth 2.0 Credentials (Empty by default in dev environment)
GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/gmail/oauth/callback")

# Initial Admin Bootstrap (if no users exist in database)
ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@scamshield.local")
ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "ScamShieldAdmin2026!")

# Production Security Gate: Fail securely if production secrets are missing or default
if not IS_DEV:
    if not os.getenv("JWT_SECRET"):
        raise RuntimeError("CRITICAL SECURITY ERROR: In production, JWT_SECRET must be explicitly set via environment variable.")
    if not os.getenv("SCAMSHIELD_WEBHOOK_SECRET") or os.getenv("SCAMSHIELD_WEBHOOK_SECRET") == "scm_live_sec_token_9921_hackathon":
        raise RuntimeError("CRITICAL SECURITY ERROR: In production, SCAMSHIELD_WEBHOOK_SECRET must be configured with a secure unique secret.")
    if not os.getenv("ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD") == "ScamShieldAdmin2026!":
        raise RuntimeError("CRITICAL SECURITY ERROR: In production, ADMIN_PASSWORD must be configured with a secure unique password.")

# Input Validation Limits
MAX_SENDER_LEN: int = 320
MAX_SUBJECT_LEN: int = 500
MAX_BODY_LEN: int = 100000
MAX_URL_LEN: int = 2048

# FalkorDB Graph Database Configuration
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "127.0.0.1")
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))
_raw_falkor_pwd = os.getenv("FALKORDB_PASSWORD")
FALKORDB_PASSWORD: Optional[str] = _raw_falkor_pwd if _raw_falkor_pwd else None
FALKORDB_GRAPH: str = os.getenv("FALKORDB_GRAPH", "scamshield")
FALKORDB_SSL: bool = os.getenv("FALKORDB_SSL", "false").lower() in ("true", "1", "yes")
FALKORDB_TIMEOUT_MS: int = int(os.getenv("FALKORDB_TIMEOUT_MS", "3000"))
