from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import httpx
import os
import sqlite3
import secrets
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

app = FastAPI(title="Number Info API")
security = HTTPBasic()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

INTERNAL_PRIMARY_API = "https://number-to-api-team-only.vercel.app/api/index.js"
INTERNAL_PRIMARY_KEY = "team6months"
INTERNAL_BACKUP_API = "https://noobster-api-5xii.onrender.com/search"
INTERNAL_BACKUP_KEY = "mr_noobster"
INTERNAL_BACKUP_API_2 = "https://heated-reconstruction-till-amy.trycloudflare.com/search"

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect("apikeys.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
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
            notes TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT NOT NULL,
            number TEXT,
            status TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            ip TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ─── ADMIN AUTH ───────────────────────────────────────────────────────────────

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != ADMIN_USERNAME or credentials.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin credentials",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials.username

# ─── KEY HELPERS ──────────────────────────────────────────────────────────────

def generate_key(prefix="hm"):
    return f"{prefix}_{secrets.token_hex(16)}"

def validate_api_key(key: str):
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

def increment_usage(key: str, number: str, status: str, ip: str = ""):
    conn = get_db()
    conn.execute("UPDATE api_keys SET used_requests=used_requests+1, last_used=datetime('now') WHERE key=?", (key,))
    conn.execute("INSERT INTO request_logs (api_key, number, status, ip) VALUES (?,?,?,?)", (key, number, status, ip))
    conn.commit()
    conn.close()

def get_key_info(row) -> dict:
    used = row["used_requests"] + 1  # +1 since increment happens after this
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

    expiry_info = {
        "expires_at": "never",
        "is_expired": False
    }
    if expires_at:
        expiry_dt = datetime.fromisoformat(expires_at)
        expiry_info["expires_at"] = expiry_dt.strftime("%d %b %Y, %I:%M %p")
        expiry_info["is_expired"] = expiry_dt < datetime.now()

    return {"key_info": {**limit_info, **expiry_info}}

# ─── INTERNAL API LOGIC ───────────────────────────────────────────────────────

def transform_to_unified_format(data: dict, number: str, source: str) -> dict:
    if source == "primary":
        return {
            "status": "success",
            "developer": "@helper_man",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            "results": data.get("results", [])
        }
    elif source == "backup":
        data_obj = data.get("data", {})
        return {
            "status": "success",
            "developer": "@helper_man",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            "results": data_obj.get("data", [])
        }
    elif source == "backup2":
        return {
            "status": "success",
            "developer": "@helper_man",
            "queried_number": number,
            "timestamp": datetime.now().isoformat() + "Z",
            "results": data.get("results", [])
        }
    return None

async def fetch_from_internal_primary(number: str):
    url = f"{INTERNAL_PRIMARY_API}?api_key={INTERNAL_PRIMARY_KEY}&number={number}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and data.get("results"):
                return {"success": True, "data": transform_to_unified_format(data, number, "primary")}
            return {"success": False}
        except Exception:
            return {"success": False}

async def fetch_from_internal_backup(number: str):
    url = f"{INTERNAL_BACKUP_API}?mobile={number}&key={INTERNAL_BACKUP_KEY}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=17.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and isinstance(data.get("data"), dict):
                if data.get("data", {}).get("data", []):
                    return {"success": True, "data": transform_to_unified_format(data, number, "backup")}
            return {"success": False}
        except Exception:
            return {"success": False}

async def fetch_from_internal_backup_2(number: str):
    url = f"{INTERNAL_BACKUP_API_2}?query={number}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=17.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success" and data.get("results"):
                return {"success": True, "data": transform_to_unified_format(data, number, "backup2")}
            return {"success": False}
        except Exception:
            return {"success": False}

# ─── PUBLIC API ───────────────────────────────────────────────────────────────

@app.get("/api/number-info")
async def number_info(
    request: Request,
    number: str = Query(..., description="Indian mobile number"),
    apikey: str = Query(None, description="API key")
):
    if not apikey:
        return {
            "success": False,
            "message": "Contact @helper_man on Telegram to get your free API key",
            "error": "Missing API key"
        }

    row, reason = validate_api_key(apikey)
    if not row:
        messages = {
            "invalid_key": "Invalid API key. Contact @helper_man on Telegram.",
            "key_disabled": "Your API key has been disabled. Contact @helper_man.",
            "key_expired": "Your API key has expired. Contact @helper_man.",
            "limit_exceeded": "Request limit reached for this key. Contact @helper_man."
        }
        return {"success": False, "error": reason, "message": messages.get(reason)}

    ip = request.client.host if request.client else ""
    key_info = get_key_info(row)

    result = await fetch_from_internal_primary(number)
    if not result["success"]:
        result = await fetch_from_internal_backup(number)
    if not result["success"]:
        result = await fetch_from_internal_backup_2(number)

    status = "success" if result["success"] else "error"
    increment_usage(apikey, number, status, ip)

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

@app.get("/")
async def root():
    return {
        "message": "Number Info API",
        "developer": "@helper_man",
        "usage": "/api/number-info?number=7439312179&apikey=YOUR_API_KEY",
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
    admin=Depends(verify_admin)
):
    key = generate_key()
    expires_at = None
    if expires_days > 0:
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO api_keys (key, label, max_requests, expires_at, notes) VALUES (?,?,?,?,?)",
        (key, label, max_requests, expires_at, notes)
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
    recent_logs = conn.execute(
        "SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "total_requests": total_requests,
        "today_requests": today_requests,
        "success_requests": success_requests,
        "recent_logs": [dict(r) for r in recent_logs]
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

# ─── ADMIN PANEL HTML ─────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return HTMLResponse(open("admin.html").read())
