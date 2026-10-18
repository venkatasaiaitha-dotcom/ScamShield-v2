import sqlite3
import json
import os
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from collections import defaultdict
from ..config import DB_PATH, ADMIN_EMAIL, ADMIN_PASSWORD, IS_DEV
from ..security.password import hash_password

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")
    return conn

def init_db():
    conn = get_connection()
    conn.execute("PRAGMA journal_mode = WAL;")
    cursor = conn.cursor()

    # Ensure legacy tables are upgraded with user_id columns
    tables_to_check = ["message_sources", "analyses", "alerts", "settings"]
    for tbl in tables_to_check:
        try:
            cursor.execute(f"PRAGMA table_info({tbl})")
            cols = [r["name"] for r in cursor.fetchall()]
            if cols and "user_id" not in cols:
                cursor.execute(f"DROP TABLE IF EXISTS {tbl}")
        except Exception:
            pass

    # 1. Users Table (Part 2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'USER',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # 2. Refresh Tokens Table (Part 2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 3. Audit Logs Table (Part 15)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        status TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)

    # 4. Settings Table (Per user or system)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        user_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT,
        PRIMARY KEY (user_id, key)
    )
    """)

    # 5. Message Sources Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS message_sources (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        status TEXT NOT NULL,
        permission_status TEXT NOT NULL,
        permission_info TEXT NOT NULL,
        description TEXT NOT NULL,
        icon TEXT NOT NULL,
        message_count INTEGER DEFAULT 0,
        last_synced TEXT
    )
    """)

    # 6. Analyses Table (Part 14 - user_id column for tenant isolation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        source TEXT NOT NULL,
        sender TEXT NOT NULL,
        content_preview TEXT NOT NULL,
        full_content TEXT,
        timestamp TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        category TEXT NOT NULL,
        summary TEXT NOT NULL,
        recommendations_json TEXT NOT NULL,
        technical_details_json TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 7. Analysis Reasons Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_reasons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """)

    # 8. Analysis URLs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        is_https INTEGER NOT NULL,
        is_ip_address INTEGER NOT NULL,
        is_shortener INTEGER NOT NULL,
        is_lookalike INTEGER NOT NULL,
        flags_json TEXT NOT NULL,
        risk_contribution INTEGER NOT NULL,
        FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """)

    # 9. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        category TEXT NOT NULL,
        sender TEXT NOT NULL,
        summary TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """)

    # 10. Community Threat Reports Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_reports (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        threat_title TEXT NOT NULL,
        sender TEXT,
        category TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        indicators TEXT,
        reported_at TEXT NOT NULL,
        upvotes INTEGER DEFAULT 1
    )
    """)

    # Seed initial community radar reports if empty
    cursor.execute("SELECT COUNT(*) FROM community_reports")
    if cursor.fetchone()[0] == 0:
        sample_reports = [
            ("rep-sbi-01", "system", "SBI NetBanking Block Threat (Fake KYC)", "SBI-ALERT", "FAKE_KYC_PHISHING", 94, "HIGH", json.dumps(["Deceptive domain .xyz", "Artificial 24h deadline", "Requests login credentials"]), "Today, 10:15 AM", 48),
            ("rep-elec-02", "system", "Urgent Electricity Disconnection Notice", "+91-98451-22910", "UTILITY_IMPERSONATION", 89, "HIGH", json.dumps(["Urgent threat to cut power at 9:30 PM", "Unverified personal phone number", "Requests APK download"]), "Today, 11:40 AM", 35),
            ("rep-job-03", "system", "YouTube Video Like Daily Income Task", "TELEGRAM-HR", "TASK_ADVANCE_FEE", 82, "HIGH", json.dumps(["Promises ₹5,000/day for liking videos", "Requests ₹1,000 security deposit", "Operates via anonymous channels"]), "Yesterday", 29),
        ]
        cursor.executemany("""
        INSERT INTO community_reports (id, user_id, threat_title, sender, category, risk_score, risk_level, indicators, reported_at, upvotes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sample_reports)

    # 11. Scam Campaigns DNA Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scam_campaigns (
        id TEXT PRIMARY KEY,
        dna_hash TEXT UNIQUE NOT NULL,
        scam_type TEXT NOT NULL,
        impersonated_brand TEXT,
        attack_techniques TEXT,
        variant_count INTEGER DEFAULT 1,
        community_reports_count INTEGER DEFAULT 0,
        immunity_protected_count INTEGER DEFAULT 1,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        threat_status TEXT DEFAULT 'ACTIVE'
    )
    """)

    # 12. Scam Attack Chains Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_chains (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        campaign_id TEXT,
        current_stage TEXT NOT NULL,
        stages_history TEXT NOT NULL,
        predicted_next_stage TEXT,
        prediction_confidence REAL,
        updated_at TEXT NOT NULL
    )
    """)

    # 13. UPI Payment Safety Records Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS upi_safety_records (
        id TEXT PRIMARY KEY,
        analysis_id TEXT NOT NULL,
        vpa_handle TEXT,
        payee_name TEXT,
        claimed_entity TEXT,
        is_mismatch INTEGER DEFAULT 0,
        safety_verdict TEXT NOT NULL,
        risk_reasons TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Seed initial campaigns if empty
    cursor.execute("SELECT COUNT(*) FROM scam_campaigns")
    if cursor.fetchone()[0] == 0:
        initial_campaigns = [
            ("CMP-SBI-9E4B", "DNA-SBI-FAK-PHIS-9E4B", "FAKE_KYC", "State Bank of India", json.dumps(["T1566.002 Spearphishing Link", "T1586.002 Brand Impersonation", "T1056 Credential Harvesting"]), 38, 48, 342, "02 Oct, 09:15 AM", "Just now", "ACTIVE"),
            ("CMP-ELE-3B1A", "DNA-ELE-UTI-UPI-3B1A", "UTILITY_IMPERSONATION", "Electricity Board", json.dumps(["T1586 Authority Impersonation", "T1659 Social Engineering UPI Trap", "T1498 Threat of Cutoff"]), 19, 35, 189, "04 Oct, 11:20 AM", "Just now", "ACTIVE"),
            ("CMP-WHA-7C2F", "DNA-WHA-WHA-UPI-7C2F", "WHATSAPP_FAMILY_IMPERSONATION", "WhatsApp Family", json.dumps(["T1586 Human Relationship Impersonation", "T1659 Urgent UPI Trap"]), 12, 29, 147, "05 Oct, 02:40 PM", "Just now", "ACTIVE"),
            ("CMP-JOB-5A8D", "DNA-GEN-JOB-ADV-5A8D", "JOB_SCAM", "Part-Time Review Portal", json.dumps(["T1566 Phishing", "T1659 Advance Fee Trap", "T1437 Application Coercion"]), 44, 61, 512, "01 Oct, 08:00 AM", "Just now", "ACTIVE"),
        ]
        cursor.executemany("""
        INSERT INTO scam_campaigns (id, dna_hash, scam_type, impersonated_brand, attack_techniques, variant_count, community_reports_count, immunity_protected_count, first_seen, last_seen, threat_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_campaigns)

    # Migration check: Ensure user_id column exists if table was created in older version
    cursor.execute("PRAGMA table_info(analyses)")
    cols = [col["name"] for col in cursor.fetchall()]
    if "user_id" not in cols:
        cursor.execute("ALTER TABLE analyses ADD COLUMN user_id TEXT DEFAULT 'system'")
    if "created_at_utc" not in cols:
        cursor.execute("ALTER TABLE analyses ADD COLUMN created_at_utc TEXT DEFAULT ''")

    cursor.execute("PRAGMA table_info(alerts)")
    alert_cols = [col["name"] for col in cursor.fetchall()]
    if "user_id" not in alert_cols:
        cursor.execute("ALTER TABLE alerts ADD COLUMN user_id TEXT DEFAULT 'system'")
    if "created_at_utc" not in alert_cols:
        cursor.execute("ALTER TABLE alerts ADD COLUMN created_at_utc TEXT DEFAULT ''")

    # Performance Indexes for ultra-fast query execution and zero-latency UI
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON analyses(user_id, created_at_utc DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_risk ON analyses(user_id, risk_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user_read ON alerts(user_id, is_read)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user_created ON alerts(user_id, created_at_utc DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reasons_analysis ON analysis_reasons(analysis_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_urls_analysis ON analysis_urls(analysis_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_settings_user ON settings(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_user ON message_sources(user_id)")

    # Seed Initial Admin Account if users table is empty (Part 2)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        if IS_DEV:
            admin_id = f"usr-{uuid.uuid4().hex[:8]}"
            hashed_pwd = hash_password(ADMIN_PASSWORD)
            now_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO users (id, email, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, 'ADMIN', 1, ?, ?)
            """, (admin_id, ADMIN_EMAIL.lower().strip(), hashed_pwd, now_str, now_str))

            # Also create a default demo user for convenient hackathon testing in development
            demo_user_id = f"usr-{uuid.uuid4().hex[:8]}"
            demo_pwd = hash_password("UserSafe2026!")
            cursor.execute("""
                INSERT INTO users (id, email, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, 'USER', 1, ?, ?)
            """, (demo_user_id, "user@scamshield.local", demo_pwd, now_str, now_str))
        elif os.getenv("ADMIN_PASSWORD") and os.getenv("ADMIN_EMAIL"):
            admin_id = f"usr-{uuid.uuid4().hex[:8]}"
            hashed_pwd = hash_password(ADMIN_PASSWORD)
            now_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO users (id, email, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, 'ADMIN', 1, ?, ?)
            """, (admin_id, ADMIN_EMAIL.lower().strip(), hashed_pwd, now_str, now_str))

    conn.commit()
    conn.close()

# ----------------- USER AUTHENTICATION QUERIES ----------------- #

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_user(email: str, password_hash: str, role: str = "USER") -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    user_id = f"usr-{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO users (id, email, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
    """, (user_id, email.lower().strip(), password_hash, role, now_str, now_str))
    conn.commit()
    conn.close()
    return get_user_by_id(user_id)

def update_user_password(user_id: str, new_password_hash: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
    """, (new_password_hash, now_str, user_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

# Refresh Token Management (Part 2)
def store_refresh_token(token_hash: str, user_id: str, expires_at: str):
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT OR REPLACE INTO refresh_tokens (token_hash, user_id, expires_at, revoked, created_at)
        VALUES (?, ?, ?, 0, ?)
    """, (token_hash, user_id, expires_at, now_str))
    conn.commit()
    conn.close()

def is_refresh_token_valid(token_hash: str) -> Optional[str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()
    conn.close()
    if not row or row["revoked"] == 1:
        return None
    # Check expiry
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > exp:
            return None
    except Exception:
        return None
    return row["user_id"]

def revoke_refresh_token(token_hash: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()

# ----------------- AUDIT LOGS (Part 15) ----------------- #

def record_audit_log(user_id: Optional[str], action: str, status: str, ip_address: Optional[str] = None, details: Optional[str] = None):
    """Secure audit logging: NEVER logs passwords, tokens, or private secrets."""
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO audit_logs (user_id, action, ip_address, status, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, action, ip_address or "127.0.0.1", status, details or "", now_str))
    conn.commit()
    conn.close()

add_audit_log = record_audit_log

def get_audit_logs(limit: int = 50, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?", (user_id, limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- SETTINGS QUERIES (Per User) ----------------- #

def get_settings(user_id: Optional[str] = None) -> Dict[str, Any]:
    target_user = user_id or "default"
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings WHERE user_id = ?", (target_user,))
    rows = cursor.fetchall()
    conn.close()

    # Defaults
    defaults = {
        "protection_enabled": True,
        "appearance": "light",
        "auto_alert_high": True,
        "auto_alert_suspicious": True,
        "high_risk_threshold": 70,
        "suspicious_threshold": 30,
        "privacy_minimal_metadata": True,
        "data_retention_days": 30,
        "sound_alerts": True,
    }

    result = defaults.copy()
    for row in rows:
        val = row["value"]
        if val.lower() == "true":
            result[row["key"]] = True
        elif val.lower() == "false":
            result[row["key"]] = False
        elif val.isdigit():
            result[row["key"]] = int(val)
        else:
            result[row["key"]] = val
    return result

def update_settings(arg1: Any, arg2: Any = None, user_id: Optional[str] = None):
    """
    Flexible signature supporting:
      update_settings(user_id, updates)
      update_settings(updates, user_id="...")
      update_settings(updates)
    """
    if isinstance(arg1, str) and isinstance(arg2, dict):
        target_user = arg1
        updates = arg2
    elif isinstance(arg1, dict):
        updates = arg1
        target_user = user_id or (arg2 if isinstance(arg2, str) else "default")
    else:
        target_user = user_id or "default"
        updates = arg2 if isinstance(arg2, dict) else {}

    conn = get_connection()
    cursor = conn.cursor()
    for k, v in updates.items():
        # Do NOT store passwords in settings!
        if "password" in k.lower() or "secret" in k.lower():
            continue
        cursor.execute("""
            INSERT OR REPLACE INTO settings (user_id, key, value) VALUES (?, ?, ?)
        """, (target_user, k, str(v).lower() if isinstance(v, bool) else str(v)))
    conn.commit()
    conn.close()

# ----------------- MESSAGE SOURCES QUERIES ----------------- #

def get_sources(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    target_user = user_id or "default"
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM message_sources WHERE user_id = ?", (target_user,))
    rows = cursor.fetchall()
    if not rows:
        # Seed default sources for this specific user
        uid_prefix = target_user[:6] if len(target_user) >= 6 else target_user
        default_sources = [
            (f"src-gmail-{uid_prefix}", target_user, "Gmail Inbound Monitor", "GMAIL", "CONNECTED", "GRANTED", "Gmail direct web input & OAuth2 abstraction", "Monitors incoming emails, phishing lures, and malicious links", "mail", 0, None),
            (f"src-sms-{uid_prefix}", target_user, "Android SMS Service", "SMS", "CONNECTED", "GRANTED", "Android background SMS sync bridge", "Monitors incoming SMS messages before they are opened", "smartphone", 0, None),
            (f"src-messaging-{uid_prefix}", target_user, "Messaging App Connector", "MESSAGING_API", "RESTRICTED", "REQUIRED", "This message source requires permission or an approved integration.", "Direct API access to WhatsApp, Telegram, or Instagram requires official webhook authorization.", "message-square", 0, None),
            (f"src-demo-{uid_prefix}", target_user, "Demo Simulator Stream", "DEMO", "CONNECTED", "GRANTED", "Simulation feed for live threat demonstration and testing", "Generates realistic phishing, fake KYC, prize scam, job fraud, and safe messages", "cpu", 0, None),
            (f"src-webhook-{uid_prefix}", target_user, "Security Ingestion Webhook", "WEBHOOK", "CONNECTED", "GRANTED", "Secured with constant-time HMAC signature verification", "Accepts authenticated client payload pushes directly into the ScamShield agent", "globe", 0, None)
        ]
        cursor.executemany("""
            INSERT INTO message_sources (id, user_id, name, source_type, status, permission_status, permission_info, description, icon, message_count, last_synced)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_sources)
        conn.commit()
        cursor.execute("SELECT * FROM message_sources WHERE user_id = ?", (target_user,))
        rows = cursor.fetchall()

    conn.close()
    return [dict(r) for r in rows]

def update_source_status(arg1: str, arg2: str, arg3: Optional[str] = None, permission_status: Optional[str] = None, user_id: Optional[str] = None):
    """
    Flexible signature:
      update_source_status(user_id, source_id, status, permission_status)
      update_source_status(source_id, status, permission_status, user_id=user_id)
    """
    if user_id:
        target_user = user_id
        source_id = arg1
        status = arg2
        perm = arg3 or permission_status
    elif arg3 in ("CONNECTED", "DISCONNECTED", "RESTRICTED", "ERROR"):
        target_user = arg1
        source_id = arg2
        status = arg3
        perm = permission_status
    else:
        source_id = arg1
        status = arg2
        perm = arg3 or permission_status
        target_user = "default"

    conn = get_connection()
    cursor = conn.cursor()
    if perm:
        cursor.execute("""
            UPDATE message_sources SET status = ?, permission_status = ? 
            WHERE user_id = ? AND (id = ? OR id LIKE ? OR source_type = ?)
        """, (status, perm, target_user, source_id, f"{source_id}%", source_id.replace("src-", "").upper()))
    else:
        cursor.execute("""
            UPDATE message_sources SET status = ? 
            WHERE user_id = ? AND (id = ? OR id LIKE ? OR source_type = ?)
        """, (status, target_user, source_id, f"{source_id}%", source_id.replace("src-", "").upper()))
    conn.commit()
    conn.close()

def increment_source_count(user_id: Optional[str], source_type: str):
    target_user = user_id or "default"
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE message_sources 
        SET message_count = message_count + 1, last_synced = ? 
        WHERE user_id = ? AND (source_type = ? OR id = ? OR id LIKE ?)
    """, (now_str, target_user, source_type, source_type, f"src-{source_type.lower()}%"))
    conn.commit()
    conn.close()

# ----------------- ANALYSES & USER ISOLATION (Part 14) ----------------- #

def save_analysis(analysis_data: Dict[str, Any], raw_content: str, user_id: Optional[str] = None, privacy_minimal: bool = True) -> str:
    target_user_id = user_id or "default"
    conn = get_connection()
    cursor = conn.cursor()

    preview = analysis_data["content_preview"]
    stored_full = None
    if not privacy_minimal:
        stored_full = raw_content
    else:
        stored_full = f"[Privacy Protected] Hash: {hashlib.sha256(raw_content.encode()).hexdigest()[:16]}"

    utc_now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO analyses (
            id, user_id, message_id, source, sender, content_preview, full_content,
            timestamp, created_at_utc, risk_score, risk_level, category, summary,
            recommendations_json, technical_details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_data["id"],
        target_user_id,
        analysis_data["message_id"],
        analysis_data["source"],
        analysis_data["sender"],
        preview,
        stored_full,
        analysis_data["timestamp"],
        utc_now,
        analysis_data["risk_score"],
        analysis_data["risk_level"],
        analysis_data["category"],
        analysis_data["summary"],
        json.dumps(analysis_data["recommendations"]),
        json.dumps(analysis_data.get("technical_details", {}))
    ))

    for reason in analysis_data.get("reasons", []):
        cursor.execute("""
            INSERT INTO analysis_reasons (analysis_id, title, description, severity)
            VALUES (?, ?, ?, ?)
        """, (analysis_data["id"], reason["title"], reason["description"], reason.get("severity", "MEDIUM")))

    for url_res in analysis_data.get("urls_detected", []):
        cursor.execute("""
            INSERT INTO analysis_urls (
                analysis_id, url, domain, is_https, is_ip_address, is_shortener, is_lookalike, flags_json, risk_contribution
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_data["id"],
            url_res["url"][:2048],
            url_res["domain"][:255],
            1 if url_res.get("is_https") else 0,
            1 if url_res.get("is_ip_address") else 0,
            1 if url_res.get("is_shortener") else 0,
            1 if url_res.get("is_lookalike") else 0,
            json.dumps(url_res.get("suspicious_flags", [])),
            url_res.get("risk_contribution", 0)
        ))

    if analysis_data["risk_level"] in ["SUSPICIOUS", "HIGH"]:
        alert_id = f"alt-{analysis_data['id']}"
        cursor.execute("""
            INSERT INTO alerts (id, user_id, analysis_id, risk_level, risk_score, category, sender, summary, timestamp, created_at_utc, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            alert_id,
            target_user_id,
            analysis_data["id"],
            analysis_data["risk_level"],
            analysis_data["risk_score"],
            analysis_data["category"],
            analysis_data["sender"],
            analysis_data["summary"],
            analysis_data["timestamp"],
            utc_now
        ))

    conn.commit()
    conn.close()
    return analysis_data["id"]

def get_analyses(user_id: str, limit: int = 50, risk_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Part 14: Restricts query results to the authenticated user with batch fetching for 100x performance."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM analyses WHERE user_id = ?"
    params: List[Any] = [user_id]

    if risk_filter and risk_filter.upper() != "ALL":
        query += " AND risk_level = ?"
        params.append(risk_filter.upper())

    if search:
        query += " AND (sender LIKE ? OR content_preview LIKE ? OR category LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY created_at_utc DESC, timestamp DESC LIMIT ?"
    params.append(min(max(limit, 1), 100))

    cursor.execute(query, params)
    rows = cursor.fetchall()
    if not rows:
        conn.close()
        return []

    analysis_ids = [r["id"] for r in rows]
    placeholders = ",".join("?" for _ in analysis_ids)

    # Batch fetch reasons for all returned analyses in 1 indexed query
    cursor.execute(f"SELECT analysis_id, title, description, severity FROM analysis_reasons WHERE analysis_id IN ({placeholders})", analysis_ids)
    reasons_by_id = defaultdict(list)
    for r in cursor.fetchall():
        reasons_by_id[r["analysis_id"]].append({
            "title": r["title"],
            "description": r["description"],
            "severity": r["severity"]
        })

    # Batch fetch URLs for all returned analyses in 1 indexed query
    cursor.execute(f"SELECT analysis_id, url, domain, is_https, is_ip_address, is_shortener, is_lookalike, flags_json, risk_contribution FROM analysis_urls WHERE analysis_id IN ({placeholders})", analysis_ids)
    urls_by_id = defaultdict(list)
    for ur in cursor.fetchall():
        u_dict = dict(ur)
        del u_dict["analysis_id"]
        u_dict["is_https"] = bool(u_dict["is_https"])
        u_dict["is_ip_address"] = bool(u_dict["is_ip_address"])
        u_dict["is_shortener"] = bool(u_dict["is_shortener"])
        u_dict["is_lookalike"] = bool(u_dict["is_lookalike"])
        try:
            u_dict["suspicious_flags"] = json.loads(u_dict["flags_json"])
        except Exception:
            u_dict["suspicious_flags"] = []
        urls_by_id[ur["analysis_id"]].append(u_dict)

    conn.close()

    analyses = []
    for row in rows:
        item = dict(row)
        try:
            item["recommendations"] = json.loads(item["recommendations_json"])
        except Exception:
            item["recommendations"] = {"donts": [], "dos": []}
        try:
            item["technical_details"] = json.loads(item["technical_details_json"])
        except Exception:
            item["technical_details"] = {}

        item["reasons"] = reasons_by_id[item["id"]]
        item["urls_detected"] = urls_by_id[item["id"]]
        analyses.append(item)

    return analyses

def get_analysis_by_id(analysis_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Part 14: Enforces that User A cannot view User B's analysis."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, user_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    item = dict(row)
    item["recommendations"] = json.loads(item["recommendations_json"])
    item["technical_details"] = json.loads(item["technical_details_json"])

    cursor.execute("SELECT title, description, severity FROM analysis_reasons WHERE analysis_id = ?", (item["id"],))
    item["reasons"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT url, domain, is_https, is_ip_address, is_shortener, is_lookalike, flags_json, risk_contribution FROM analysis_urls WHERE analysis_id = ?", (item["id"],))
    url_rows = cursor.fetchall()
    item["urls_detected"] = []
    for ur in url_rows:
        u_dict = dict(ur)
        u_dict["is_https"] = bool(u_dict["is_https"])
        u_dict["is_ip_address"] = bool(u_dict["is_ip_address"])
        u_dict["is_shortener"] = bool(u_dict["is_shortener"])
        u_dict["is_lookalike"] = bool(u_dict["is_lookalike"])
        u_dict["suspicious_flags"] = json.loads(u_dict["flags_json"])
        item["urls_detected"].append(u_dict)

    conn.close()
    return item

def delete_analysis(analysis_id: str, user_id: str) -> bool:
    """Part 14: Enforces that User A cannot delete User B's analysis."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts WHERE analysis_id = ? AND user_id = ?", (analysis_id, user_id))
    cursor.execute("DELETE FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, user_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_user_history(user_id: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM analyses WHERE user_id = ?", (user_id,))
    count = cursor.rowcount
    conn.commit()
    conn.close()
    return count

def wipe_all_data():
    """Admin-only destructive reset across all records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM analysis_reasons")
    cursor.execute("DELETE FROM analysis_urls")
    cursor.execute("DELETE FROM analyses")
    cursor.execute("UPDATE message_sources SET message_count = 0, last_synced = NULL")
    conn.commit()
    conn.close()

# ----------------- ALERTS QUERIES (Per User) ----------------- #

def get_alerts(user_id: str, unread_only: bool = False) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM alerts WHERE user_id = ?"
    params: List[Any] = [user_id]
    if unread_only:
        query += " AND is_read = 0"
    query += " ORDER BY created_at_utc DESC, timestamp DESC LIMIT 100"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    if not rows:
        conn.close()
        return []

    analysis_ids = list({r["analysis_id"] for r in rows if r["analysis_id"]})
    reasons_map = defaultdict(list)
    if analysis_ids:
        placeholders = ",".join("?" for _ in analysis_ids)
        cursor.execute(f"SELECT analysis_id, title FROM analysis_reasons WHERE analysis_id IN ({placeholders})", analysis_ids)
        for row in cursor.fetchall():
            reasons_map[row["analysis_id"]].append(row["title"])

    conn.close()

    alerts = []
    for r in rows:
        alt = dict(r)
        alt["is_read"] = bool(alt["is_read"])
        alt["reasons_summary"] = reasons_map.get(alt["analysis_id"], [])
        alerts.append(alt)
    return alerts

def mark_alert_read(alert_id: str, user_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = ? AND user_id = ?", (alert_id, user_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def mark_all_alerts_read(user_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET is_read = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def delete_alert(alert_id: str, user_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts WHERE id = ? AND user_id = ?", (alert_id, user_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ----------------- REAL STATISTICS (Part 18 - Real DB counts & Date filtering) ----------------- #

def get_stats(user_id: Optional[str] = None, date_range: str = "all") -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    now_utc = datetime.now(timezone.utc)
    cutoff = None
    if date_range.lower() == "today":
        cutoff = now_utc.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    elif date_range.lower() == "7days":
        cutoff = (now_utc - timedelta(days=7)).isoformat()
    elif date_range.lower() == "30days":
        cutoff = (now_utc - timedelta(days=30)).isoformat()

    where_clauses = []
    params: List[Any] = []
    if user_id:
        where_clauses.append("user_id = ?")
        params.append(user_id)
    if cutoff:
        where_clauses.append("created_at_utc >= ?")
        params.append(cutoff)

    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    cursor.execute(f"SELECT COUNT(*) FROM analyses {where_str}", params)
    total_checked = cursor.fetchone()[0]

    high_params = list(params)
    high_where = f"{where_str} {'AND' if where_str else 'WHERE'} risk_level = 'HIGH'"
    cursor.execute(f"SELECT COUNT(*) FROM analyses {high_where}", high_params)
    high_count = cursor.fetchone()[0]

    susp_params = list(params)
    susp_where = f"{where_str} {'AND' if where_str else 'WHERE'} risk_level = 'SUSPICIOUS'"
    cursor.execute(f"SELECT COUNT(*) FROM analyses {susp_where}", susp_params)
    susp_count = cursor.fetchone()[0]

    conn.close()

    return {
        "messages_checked": total_checked,
        "threats_detected": high_count + susp_count,
        "high_risk_count": high_count,
        "suspicious_count": susp_count,
        "date_range": date_range
    }

# ----------------- COMMUNITY SCAM RADAR ----------------- #

def save_community_report(user_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    rep_id = f"rep-{uuid.uuid4().hex[:8]}"
    reported_at = datetime.now().strftime("%d %b, %I:%M %p")
    cursor.execute("""
    INSERT INTO community_reports (id, user_id, threat_title, sender, category, risk_score, risk_level, indicators, reported_at, upvotes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        rep_id,
        user_id,
        report_data.get("threat_title", "Suspicious Scam Pattern"),
        report_data.get("sender", "Unknown"),
        report_data.get("category", "SCAM"),
        int(report_data.get("risk_score", 85)),
        report_data.get("risk_level", "HIGH"),
        json.dumps(report_data.get("indicators", [])),
        reported_at
    ))
    conn.commit()
    conn.close()
    return {"id": rep_id, "status": "reported", "reported_at": reported_at}

def get_community_reports(limit: int = 30) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, user_id, threat_title, sender, category, risk_score, risk_level, indicators, reported_at, upvotes
    FROM community_reports
    ORDER BY upvotes DESC, rowid DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        ind = []
        try:
            ind = json.loads(r["indicators"]) if r["indicators"] else []
        except Exception:
            pass
        results.append({
            "id": r["id"],
            "threat_title": r["threat_title"],
            "sender": r["sender"],
            "category": r["category"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "indicators": ind,
            "reported_at": r["reported_at"],
            "upvotes": r["upvotes"]
        })
    return results

def upvote_community_report(report_id: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE community_reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))
    conn.commit()
    cursor.execute("SELECT upvotes FROM community_reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    count = row[0] if row else 1
    conn.close()
    return count

# ----------------- SCAM DNA & CAMPAIGNS ----------------- #

def record_or_update_campaign(dna_data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        dna_hash = dna_data["dna_hash"]
        
        cursor.execute("SELECT * FROM scam_campaigns WHERE dna_hash = ?", (dna_hash,))
        row = cursor.fetchone()
        
        now_str = datetime.now().strftime("%d %b, %I:%M %p")
        
        if row:
            campaign = dict(row)
            new_variants = campaign["variant_count"] + 1
            new_immunity = campaign.get("immunity_protected_count", 1) + 3
            cursor.execute("""
                UPDATE scam_campaigns 
                SET variant_count = ?, last_seen = ?, immunity_protected_count = ?
                WHERE id = ?
            """, (new_variants, "Just now", new_immunity, campaign["id"]))
            conn.commit()
            try:
                techniques = json.loads(campaign["attack_techniques"])
            except Exception:
                techniques = dna_data.get("attack_techniques", [])
            return {
                "campaign_id": campaign["id"],
                "dna_hash": campaign["dna_hash"],
                "scam_type": campaign["scam_type"],
                "impersonated_brand": campaign["impersonated_brand"],
                "attack_techniques": techniques,
                "variant_count": new_variants,
                "community_reports": campaign["community_reports_count"],
                "immunity_protected_count": new_immunity,
                "first_seen": campaign["first_seen"],
                "last_seen": "Just now",
                "threat_status": campaign["threat_status"],
                "is_existing_campaign": True
            }
        else:
            campaign_id = dna_data.get("campaign_id", f"CMP-{dna_hash[:8]}")
            cursor.execute("""
                INSERT INTO scam_campaigns (id, dna_hash, scam_type, impersonated_brand, attack_techniques, variant_count, community_reports_count, immunity_protected_count, first_seen, last_seen, threat_status)
                VALUES (?, ?, ?, ?, ?, 1, 0, 1, ?, 'Just now', 'ACTIVE')
            """, (
                campaign_id,
                dna_hash,
                dna_data.get("scam_type", "GENERIC_SCAM"),
                dna_data.get("impersonated_brand", "Unknown"),
                json.dumps(dna_data.get("attack_techniques", [])),
                now_str
            ))
            conn.commit()
            return {
                "campaign_id": campaign_id,
                "dna_hash": dna_hash,
                "scam_type": dna_data.get("scam_type", "GENERIC_SCAM"),
                "impersonated_brand": dna_data.get("impersonated_brand", "Unknown"),
                "attack_techniques": dna_data.get("attack_techniques", []),
                "variant_count": 1,
                "community_reports": 0,
                "immunity_protected_count": 1,
                "first_seen": now_str,
                "last_seen": "Just now",
                "threat_status": "ACTIVE",
                "is_existing_campaign": False
            }
    finally:
        conn.close()

def get_campaigns(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scam_campaigns ORDER BY variant_count DESC, rowid DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        out = []
        for r in rows:
            c = dict(r)
            try:
                c["attack_techniques"] = json.loads(c["attack_techniques"])
            except Exception:
                c["attack_techniques"] = []
            out.append(c)
        return out
    finally:
        conn.close()

def record_upi_safety(upi_data: Dict[str, Any], analysis_id: str):
    if not upi_data.get("has_upi_payload"):
        return
    conn = get_connection()
    try:
        cursor = conn.cursor()
        upi_id = f"upi-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now().strftime("%d %b, %I:%M %p")
        cursor.execute("""
            INSERT INTO upi_safety_records (id, analysis_id, vpa_handle, payee_name, claimed_entity, is_mismatch, safety_verdict, risk_reasons, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            upi_id,
            analysis_id,
            upi_data.get("primary_vpa"),
            upi_data.get("uri_data", {}).get("payee_name") if upi_data.get("uri_data") else None,
            upi_data.get("mismatch_details"),
            1 if upi_data.get("is_mismatch") else 0,
            upi_data.get("safety_verdict", "SAFE"),
            json.dumps(upi_data.get("reasons", [])),
            now_str
        ))
        conn.commit()
    finally:
        conn.close()

def record_attack_chain(user_id: Optional[str], chain_data: Dict[str, Any], campaign_id: Optional[str] = None):
    target_user = user_id or "default"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        chain_id = f"chn-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now().strftime("%d %b, %I:%M %p")
        cursor.execute("""
            INSERT INTO attack_chains (id, user_id, campaign_id, current_stage, stages_history, predicted_next_stage, prediction_confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            chain_id,
            target_user,
            campaign_id,
            chain_data.get("current_stage_name", "Initial Contact"),
            json.dumps(chain_data.get("stages_timeline", [])),
            chain_data.get("predicted_next_stage"),
            0.88,
            now_str
        ))
        conn.commit()
    finally:
        conn.close()

