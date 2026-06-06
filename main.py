from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.base import BaseHTTPMiddleware
import httpx
import os
import sqlite3
import secrets
import time
import hashlib
import asyncio
from collections import defaultdict, deque
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional

load_dotenv()

app = FastAPI(title="Number Info API", docs_url=None, redoc_url=None)  # Hide docs in prod
security = HTTPBasic()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

INTERNAL_PRIMARY_API = "https://number-to-api-team-only.vercel.app/api/index.js"
INTERNAL_PRIMARY_KEY = "team6months"
INTERNAL_BACKUP_API = "https://heated-reconstruction-till-amy.trycloudflare.com/search"
INTERNAL_BACKUP_API_2 = "https://noobster-api-5xii.onrender.com/search"
INTERNAL_BACKUP_KEY = "mr_noobster"

TG_TO_NUM_API = "http://Api.subhxcosmo.in/api"
TG_TO_NUM_KEY = "KRISHRDP2"

# ─── RATE LIMIT CONFIG ────────────────────────────────────────────────────────

# Per-IP rate limiting (sliding window)
IP_RATE_LIMIT = 30           # max requests per IP
IP_RATE_WINDOW = 60          # per 60 seconds

# Per-API-key rate limiting
KEY_RATE_LIMIT = 20          # max requests per key
KEY_RATE_WINDOW = 60         # per 60 seconds

# Burst detection (too many hits in a short window = DDoS signal)
BURST_LIMIT = 15             # max requests in burst window
BURST_WINDOW = 10            # per 10 seconds

# Auto-ban thresholds
BAN_VIOLATION_COUNT = 5      # violations before auto-ban
BAN_DURATION = 1800          # ban duration in seconds (30 min)

# In-memory stores (use Redis in prod for multi-worker setups)
ip_request_log: dict[str, deque] = defaultdict(deque)       # IP -> timestamps
key_request_log: dict[str, deque] = defaultdict(deque)      # key -> timestamps
ip_burst_log: dict[str, deque] = defaultdict(deque)         # IP -> burst timestamps
ip_violations: dict[str, int] = defaultdict(int)            # IP -> violation count
ip_ban_until: dict[str, float] = {}                         # IP -> ban expiry timestamp
admin_ban_list: set[str] = set()                            # Manually banned IPs

# Cleanup lock to prevent concurrent cleanup
_cleanup_lock = asyncio.Lock()

# ─── SECURITY HEADERS MIDDLEWARE ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        # Hide server info
        response.headers["Server"] = "unknown"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ─── RATE LIMITING HELPERS ────────────────────────────────────────────────────

def get_real_ip(request: Request) -> str:
    """Extract real IP, respecting common reverse-proxy headers."""
    # Trust CF-Connecting-IP first (Cloudflare), then X-Forwarded-For, then direct
    for header in ["cf-connecting-ip", "x-real-ip"]:
        ip = request.headers.get(header)
        if ip:
            return ip.strip().split(",")[0].strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.strip().split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _prune_window(dq: deque, window: int) -> deque:
    """Remove timestamps older than `window` seconds."""
    now = time.time()
    while dq and dq[0] < now - window:
        dq.popleft()
    return dq


def is_ip_banned(ip: str) -> bool:
    if ip in admin_ban_list:
        return True
    expiry = ip_ban_until.get(ip)
    if expiry and time.time() < expiry:
        return True
    elif expiry:
        # Ban expired, clean up
        del ip_ban_until[ip]
        ip_violations[ip] = 0
    return False


def record_violation(ip: str):
    ip_violations[ip] += 1
    if ip_violations[ip] >= BAN_VIOLATION_COUNT:
        ip_ban_until[ip] = time.time() + BAN_DURATION
        log_security_event(ip, "auto_banned", f"After {ip_violations[ip]} violations")


def check_ip_rate_limit(ip: str) -> bool:
    """Returns True if allowed, False if rate-limited."""
    dq = ip_request_log[ip]
    _prune_window(dq, IP_RATE_WINDOW)
    if len(dq) >= IP_RATE_LIMIT:
        record_violation(ip)
        return False
    dq.append(time.time())
    return True


def check_key_rate_limit(key: str) -> bool:
    """Returns True if allowed, False if rate-limited."""
    dq = key_request_log[key]
    _prune_window(dq, KEY_RATE_WINDOW)
    if len(dq) >= KEY_RATE_LIMIT:
        return False
    dq.append(time.time())
    return True


def check_burst(ip: str) -> bool:
    """Returns True if allowed, False if burst detected."""
    dq = ip_burst_log[ip]
    _prune_window(dq, BURST_WINDOW)
    if len(dq) >= BURST_LIMIT:
        record_violation(ip)
        return False
    dq.append(time.time())
    return True


def get_retry_after(ip: str) -> int:
    """Seconds until the oldest request in the window expires."""
    dq = ip_request_log.get(ip)
    if dq:
        oldest = dq[0]
        return max(1, int(IP_RATE_WINDOW - (time.time() - oldest)))
    return IP_RATE_WINDOW


def rate_limit_response(retry_after: int, reason: str = "rate_limited") -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "error": reason,
            "message": "Too many requests. Slow down.",
            "retry_after_seconds": retry_after
        },
        headers={"Retry-After": str(retry_after)}
    )


def banned_response() -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "success": False,
            "error": "ip_banned",
            "message": "Your IP has been temporarily blocked due to abuse."
        }
    )

# ─── SECURITY EVENT LOG ───────────────────────────────────────────────────────

def log_security_event(ip: str, event: str, detail: str = ""):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO security_events (ip, event, detail) VALUES (?,?,?)",
            (ip, event, detail)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

# ─── PERIODIC CLEANUP ─────────────────────────────────────────────────────────

async def cleanup_old_data():
    """Periodically prune in-memory rate limit stores to prevent memory bloat."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        async with _cleanup_lock:
            now = time.time()
            for ip in list(ip_request_log.keys()):
                _prune_window(ip_request_log[ip], IP_RATE_WINDOW)
                if not ip_request_log[ip]:
                    del ip_request_log[ip]
            for key in list(key_request_log.keys()):
                _prune_window(key_request_log[key], KEY_RATE_WINDOW)
                if not key_request_log[key]:
                    del key_request_log[key]
            for ip in list(ip_burst_log.keys()):
                _prune_window(ip_burst_log[ip], BURST_WINDOW)
                if not ip_burst_log[ip]:
                    del ip_burst_log[ip]
            # Clean expired bans
            for ip in list(ip_ban_until.keys()):
                if ip_ban_until[ip] < now:
                    del ip_ban_until[ip]
                    ip_violations[ip] = 0

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_old_data())

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect("apikeys.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrent write performance
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT '',
            max_requests INTEGER DEFAULT -1,
            used_requests INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            expires_at TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            last_used TEXT DEFAULT NULL,
            notes TEXT DEFAULT '',
            allowed_ips TEXT DEFAULT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT NOT NULL,
            endpoint TEXT DEFAULT 'number-info',
            query_term TEXT,
            status TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            ip TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT DEFAULT '',
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            reason TEXT DEFAULT '',
            banned_at TEXT DEFAULT (datetime('now')),
            banned_by TEXT DEFAULT 'admin'
        )
    """)
    # Indexes for faster queries
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_key ON request_logs(api_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_ts  ON request_logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_ip      ON security_events(ip)")
    conn.commit()

    # Load persisted bans into memory
    rows = conn.execute("SELECT ip FROM banned_ips").fetchall()
    for row in rows:
        admin_ban_list.add(row["ip"])

    conn.close()

init_db()

# ─── ADMIN AUTH ───────────────────────────────────────────────────────────────

# Brute-force protection for admin login
_admin_fail_log: dict[str, deque] = defaultdict(deque)
ADMIN_FAIL_LIMIT = 10
ADMIN_FAIL_WINDOW = 300  # 5 minutes

def verify_admin(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    ip = get_real_ip(request)

    # Check if IP is banned
    if is_ip_banned(ip):
        raise HTTPException(status_code=403, detail="IP banned")

    # Check brute-force attempts
    dq = _admin_fail_log[ip]
    _prune_window(dq, ADMIN_FAIL_WINDOW)
    if len(dq) >= ADMIN_FAIL_LIMIT:
        log_security_event(ip, "admin_brute_force_blocked", "Too many failed admin logins")
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try later.")

    # Constant-time comparison to prevent timing attacks
    correct_user = secrets.compare_digest(credentials.username.encode(), ADMIN_USERNAME.encode())
    correct_pass = secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())

    if not (correct_user and correct_pass):
        dq.append(time.time())
        log_security_event(ip, "admin_login_failed", f"user={credentials.username}")
        raise HTTPException(
            status_code=401,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"}
        )
    return credentials.username

# ─── KEY HELPERS ──────────────────────────────────────────────────────────────

def generate_key(prefix="hm"):
    return f"{prefix}_{secrets.token_hex(24)}"   # longer = harder to brute-force


def validate_api_key(key: str):
    # Basic sanity check — prevent DB queries with garbage input
    if not key or len(key) > 200 or not key.replace("_", "").isalnum():
        return None, "invalid_key"

    conn = get_db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    conn.close()
    if not row:
        return None, "invalid_key"
    if not row["is_active"]:
        return None, "key_disabled"
    if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.now():
        return None, "key_expired"
    if row["max_requests"] != -1 and row["used_requests"] >= row["max_requests"]:
        return None, "limit_exceeded"
    return row, "ok"


def validate_key_ip(row, ip: str) -> bool:
    """If the key has an IP allowlist, enforce it."""
    allowed = row["allowed_ips"]
    if not allowed:
        return True
    allowed_list = [a.strip() for a in allowed.split(",") if a.strip()]
    return ip in allowed_list


def increment_usage(key: str, query_term: str, status: str, endpoint: str = "number-info", ip: str = ""):
    conn = get_db()
    conn.execute(
        "UPDATE api_keys SET used_requests=used_requests+1, last_used=datetime('now') WHERE key=?",
        (key,)
    )
    conn.execute(
        "INSERT INTO request_logs (api_key, endpoint, query_term, status, ip) VALUES (?,?,?,?,?)",
        (key, endpoint, query_term, status, ip)
    )
    conn.commit()
    conn.close()


def get_key_info(row) -> dict:
    used = row["used_requests"] + 1
    max_req = row["max_requests"]
    expires_at = row["expires_at"]

    if max_req == -1:
        limit_info = {
            "requests_used": used,
            "requests_limit": "unlimited",
            "requests_remaining": "unlimited"
        }
    else:
        limit_info = {
            "requests_used": used,
            "requests_limit": max_req,
            "requests_remaining": max(0, max_req - used)
        }

    expiry_info = {"expires_at": "never", "is_expired": False}
    if expires_at:
        expiry_dt = datetime.fromisoformat(expires_at)
        expiry_info["expires_at"] = expiry_dt.strftime("%d %b %Y, %I:%M %p")
        expiry_info["is_expired"] = expiry_dt < datetime.now()

    return {"key_info": {**limit_info, **expiry_info}}

# ─── INPUT VALIDATION ─────────────────────────────────────────────────────────

def validate_number(number: str) -> bool:
    """Basic Indian mobile number validation."""
    clean = number.strip().lstrip("+").lstrip("91")
    return clean.isdigit() and 10 <= len(clean) <= 13


def validate_username(username: str) -> bool:
    clean = username.lstrip("@")
    return 1 <= len(clean) <= 64 and all(c.isalnum() or c in "_." for c in clean)

# ─── INTERNAL API LOGIC (NUMBER TO INFO) ───────────────────────────────────────

def transform_to_unified_format(data: dict, number: str, source: str) -> dict:
    if source in ("primary", "backup"):
        return {
            "status": "success",
            "developer": "@helper_man",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            "results": data.get("results", [])
        }
    elif source == "backup2":
        data_obj = data.get("data", {})
        return {
            "status": "success",
            "developer": "@helper_man",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            "results": data_obj.get("data", [])
        }
    return None


async def fetch_from_internal_primary(number: str):
    url = f"{INTERNAL_PRIMARY_API}?api_key={INTERNAL_PRIMARY_KEY}&number={number}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=7.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and data.get("results"):
                return {"success": True, "data": transform_to_unified_format(data, number, "primary")}
            return {"success": False}
        except Exception:
            return {"success": False}


async def fetch_from_internal_backup(number: str):
    url = f"{INTERNAL_BACKUP_API}?query={number}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=7.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and data.get("results"):
                return {"success": True, "data": transform_to_unified_format(data, number, "backup")}
            return {"success": False}
        except Exception:
            return {"success": False}


async def fetch_from_internal_backup_2(number: str):
    url = f"{INTERNAL_BACKUP_API_2}?mobile={number}&key={INTERNAL_BACKUP_KEY}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and isinstance(data.get("data"), dict):
                if data.get("data", {}).get("data", []):
                    return {"success": True, "data": transform_to_unified_format(data, number, "backup2")}
            return {"success": False}
        except Exception:
            return {"success": False}

# ─── INTERNAL API LOGIC (TELEGRAM TO NUMBER) ───────────────────────────────────

async def fetch_from_tg_to_num(username: str):
    url = f"{TG_TO_NUM_API}?key={TG_TO_NUM_KEY}&type=tg&term={username}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success"):
                result = data.get("result", {})
                if result.get("success"):
                    return {
                        "success": True,
                        "data": {
                            "status": "success",
                            "developer": "@helper_man",
                            "queried_username": username,
                            "timestamp": datetime.now().isoformat() + "Z",
                            "tg_id": result.get("tg_id"),
                            "country": result.get("country"),
                            "country_code": result.get("country_code"),
                            "number": result.get("number"),
                            "msg": result.get("msg")
                        }
                    }
            return {"success": False}
        except Exception as e:
            return {"success": False}

# ─── SHARED SECURITY GATE ─────────────────────────────────────────────────────

async def security_gate(request: Request, apikey: Optional[str], query_value: str):
    """
    Runs all security checks before any endpoint logic.
    Returns (ip, row, key_info) on success, or raises/returns a JSONResponse.
    """
    ip = get_real_ip(request)

    # 1. IP ban check
    if is_ip_banned(ip):
        log_security_event(ip, "banned_ip_request")
        return None, banned_response()

    # 2. Burst / DDoS detection
    if not check_burst(ip):
        log_security_event(ip, "burst_blocked", f"query={query_value}")
        return None, rate_limit_response(BURST_WINDOW, "burst_detected")

    # 3. IP rate limit
    if not check_ip_rate_limit(ip):
        log_security_event(ip, "ip_rate_limited", f"query={query_value}")
        return None, rate_limit_response(get_retry_after(ip))

    # 4. API key presence
    if not apikey:
        return None, JSONResponse(status_code=401, content={
            "success": False,
            "message": "Contact @helper_man on Telegram to get your free API key",
            "error": "missing_api_key"
        })

    # 5. API key validation
    row, reason = validate_api_key(apikey)
    if not row:
        messages = {
            "invalid_key": "Invalid API key. Contact @helper_man on Telegram.",
            "key_disabled": "Your API key has been disabled. Contact @helper_man.",
            "key_expired": "Your API key has expired. Contact @helper_man.",
            "limit_exceeded": "Request limit reached for this key. Contact @helper_man."
        }
        return None, JSONResponse(status_code=403, content={
            "success": False,
            "error": reason,
            "message": messages.get(reason)
        })

    # 6. IP allowlist check (per-key)
    if not validate_key_ip(row, ip):
        log_security_event(ip, "key_ip_not_allowed", f"key={apikey[:10]}…")
        return None, JSONResponse(status_code=403, content={
            "success": False,
            "error": "ip_not_allowed",
            "message": "This API key is not authorized for your IP address."
        })

    # 7. Per-key rate limit
    if not check_key_rate_limit(apikey):
        return None, rate_limit_response(KEY_RATE_WINDOW, "key_rate_limited")

    return (ip, row), None

# ─── PUBLIC API ───────────────────────────────────────────────────────────────

@app.get("/api/number-info")
async def number_info(
    request: Request,
    number: str = Query(..., description="Indian mobile number", max_length=20),
    apikey: str = Query(None, description="API key", max_length=200)
):
    # Input validation
    if not validate_number(number):
        return JSONResponse(status_code=422, content={
            "success": False,
            "error": "invalid_number",
            "message": "Please provide a valid Indian mobile number."
        })

    gate_result, error_response = await security_gate(request, apikey, number)
    if error_response:
        return error_response
    ip, row = gate_result

    key_info = get_key_info(row)

    result = await fetch_from_internal_primary(number)
    if not result["success"]:
        result = await fetch_from_internal_backup(number)
    if not result["success"]:
        result = await fetch_from_internal_backup_2(number)

    status = "success" if result["success"] else "error"
    increment_usage(apikey, number, status, "number-info", ip)

    if not result["success"]:
        return {
            "status": "error",
            "success": False,
            "developer": "@helper_man",
            "message": "Service temporarily unavailable. We are working on a fix.",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            **key_info
        }

    return {**result["data"], **key_info}


@app.get("/api/tg-to-number")
async def tg_to_number(
    request: Request,
    username: str = Query(..., description="Telegram username", max_length=64),
    apikey: str = Query(None, description="API key", max_length=200)
):
    if not validate_username(username):
        return JSONResponse(status_code=422, content={
            "success": False,
            "error": "invalid_username",
            "message": "Please provide a valid Telegram username."
        })

    gate_result, error_response = await security_gate(request, apikey, username)
    if error_response:
        return error_response
    ip, row = gate_result

    key_info = get_key_info(row)
    clean_username = username.lstrip("@")

    result = await fetch_from_tg_to_num(clean_username)

    status = "success" if result["success"] else "error"
    increment_usage(apikey, clean_username, status, "tg-to-number", ip)

    if not result["success"]:
        return {
            "status": "error",
            "success": False,
            "developer": "@helper_man",
            "message": "Service temporarily unavailable or username not found.",
            "queried_username": clean_username,
            "timestamp": datetime.now().isoformat() + "Z",
            **key_info
        }

    return {**result["data"], **key_info}


@app.get("/")
async def root():
    return {
        "message": "Helper Man APIs",
        "developer": "@helper_man",
        "endpoints": {
            "number_info": "/api/number-info?number=7439312179&apikey=YOUR_API_KEY",
            "tg_to_number": "/api/tg-to-number?username=rocket_xd777&apikey=YOUR_API_KEY"
        },
        "get_api_key": "Contact @helper_man on Telegram for a free api key",
        "admin_panel": "/admin",
        "status": "active"
    }

# ─── ADMIN REST API ───────────────────────────────────────────────────────────

@app.get("/admin/api/keys")
async def list_keys(admin=Depends(verify_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/admin/api/keys")
async def create_key(
    label: str = Query(""),
    max_requests: int = Query(-1),
    expires_days: int = Query(-1),
    notes: str = Query(""),
    allowed_ips: str = Query("", description="Comma-separated IPs allowed for this key. Leave empty for any IP."),
    admin=Depends(verify_admin)
):
    key = generate_key()
    expires_at = None
    if expires_days > 0:
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO api_keys (key, label, max_requests, expires_at, notes, allowed_ips) VALUES (?,?,?,?,?,?)",
        (key, label, max_requests, expires_at, notes, allowed_ips or None)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/admin/api/keys/{key_id}")
async def delete_key(key_id: int, admin=Depends(verify_admin)):
    conn = get_db()
    conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Key deleted"}


@app.patch("/admin/api/keys/{key_id}/toggle")
async def toggle_key(key_id: int, admin=Depends(verify_admin)):
    conn = get_db()
    row = conn.execute("SELECT is_active FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Key not found")
    new_status = 0 if row["is_active"] else 1
    conn.execute("UPDATE api_keys SET is_active=? WHERE id=?", (new_status, key_id))
    conn.commit()
    conn.close()
    return {"success": True, "is_active": new_status}


@app.patch("/admin/api/keys/{key_id}")
async def update_key(
    key_id: int,
    label: str = Query(None),
    max_requests: int = Query(None),
    expires_days: int = Query(None),
    notes: str = Query(None),
    allowed_ips: str = Query(None),
    admin=Depends(verify_admin)
):
    conn = get_db()
    row = conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Key not found")

    updates = {}
    if label is not None:
        updates["label"] = label
    if max_requests is not None:
        updates["max_requests"] = max_requests
    if expires_days is not None:
        updates["expires_at"] = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if notes is not None:
        updates["notes"] = notes
    if allowed_ips is not None:
        updates["allowed_ips"] = allowed_ips or None

    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE api_keys SET {set_clause} WHERE id=?", (*updates.values(), key_id))
        conn.commit()

    row = conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
    conn.close()
    return dict(row)


@app.get("/admin/api/stats")
async def get_stats(admin=Depends(verify_admin)):
    conn = get_db()
    total_keys = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    active_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE is_active=1").fetchone()[0]
    total_requests = conn.execute("SELECT COUNT(*) FROM request_logs").fetchone()[0]
    today_requests = conn.execute(
        "SELECT COUNT(*) FROM request_logs WHERE date(timestamp)=date('now')"
    ).fetchone()[0]
    success_requests = conn.execute(
        "SELECT COUNT(*) FROM request_logs WHERE status='success'"
    ).fetchone()[0]
    number_info_requests = conn.execute(
        "SELECT COUNT(*) FROM request_logs WHERE endpoint='number-info'"
    ).fetchone()[0]
    tg_to_number_requests = conn.execute(
        "SELECT COUNT(*) FROM request_logs WHERE endpoint='tg-to-number'"
    ).fetchone()[0]
    recent_logs = conn.execute(
        "SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    # Security events
    recent_security = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    active_bans = conn.execute("SELECT * FROM banned_ips ORDER BY banned_at DESC").fetchall()
    conn.close()
    return {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "total_requests": total_requests,
        "today_requests": today_requests,
        "success_requests": success_requests,
        "number_info_requests": number_info_requests,
        "tg_to_number_requests": tg_to_number_requests,
        "recent_logs": [dict(r) for r in recent_logs],
        "recent_security_events": [dict(r) for r in recent_security],
        "active_bans": [dict(r) for r in active_bans],
        "memory_rate_limits": {
            "tracked_ips": len(ip_request_log),
            "tracked_keys": len(key_request_log),
            "auto_banned_ips": len(ip_ban_until),
            "manual_banned_ips": len(admin_ban_list)
        }
    }


@app.get("/admin/api/keys/{key_id}/logs")
async def key_logs(key_id: int, admin=Depends(verify_admin)):
    conn = get_db()
    row = conn.execute("SELECT key FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Key not found")
    logs = conn.execute(
        "SELECT * FROM request_logs WHERE api_key=? ORDER BY timestamp DESC LIMIT 100",
        (row["key"],)
    ).fetchall()
    conn.close()
    return [dict(l) for l in logs]


# ─── ADMIN: IP BAN MANAGEMENT ─────────────────────────────────────────────────

@app.post("/admin/api/ban/{ip}")
async def ban_ip(ip: str, reason: str = Query(""), admin=Depends(verify_admin)):
    admin_ban_list.add(ip)
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO banned_ips (ip, reason, banned_by) VALUES (?,?,?)",
        (ip, reason, admin)
    )
    conn.commit()
    conn.close()
    log_security_event(ip, "manually_banned", f"by={admin}, reason={reason}")
    return {"success": True, "message": f"IP {ip} banned"}


@app.delete("/admin/api/ban/{ip}")
async def unban_ip(ip: str, admin=Depends(verify_admin)):
    admin_ban_list.discard(ip)
    if ip in ip_ban_until:
        del ip_ban_until[ip]
    if ip in ip_violations:
        del ip_violations[ip]
    conn = get_db()
    conn.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    log_security_event(ip, "unbanned", f"by={admin}")
    return {"success": True, "message": f"IP {ip} unbanned"}


@app.get("/admin/api/bans")
async def list_bans(admin=Depends(verify_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM banned_ips ORDER BY banned_at DESC").fetchall()
    conn.close()
    auto_bans = {ip: exp for ip, exp in ip_ban_until.items() if time.time() < exp}
    return {
        "manual_bans": [dict(r) for r in rows],
        "auto_bans": [{"ip": ip, "expires_at": datetime.fromtimestamp(exp).isoformat()} for ip, exp in auto_bans.items()]
    }


@app.get("/admin/api/security-events")
async def security_events(admin=Depends(verify_admin), limit: int = Query(50, le=500)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── ADMIN PANEL HTML ─────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    # Reuse verify_admin logic inline so we can pass request
    verify_admin(request, credentials)
    return HTMLResponse(open("admin.html").read())
