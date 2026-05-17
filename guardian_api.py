"""
guardian_api.py — FastAPI Web Server for Guardian Dashboard
=============================================================
Serves the live dashboard, handles auth, WebSocket streaming,
OTP whitelist flow, and session history.

Usage:
    python guardian_api.py
    Then open http://localhost:8080 in your browser.
"""

import asyncio
import json
import os
import queue
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import (BackgroundTasks, Cookie, Depends, FastAPI, HTTPException, Request,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

# ── Path fix for sibling imports ──────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import guardian_db as db
import guardian_auth as auth
from guardian_db import MACHINE_ID
import guardian_actions

# ── Event Queue (Brain → WebSocket) ───────────────────────────────────────────
event_queue: queue.Queue = queue.Queue(maxsize=500)
# ── Action Queue (Web UI → Local PC) ──────────────────────────────────────────
action_queue: queue.Queue = queue.Queue(maxsize=100)

connected_clients: list = []
_client_lock = threading.Lock()

# ── Session tracking ──────────────────────────────────────────────────────────
session_stats = {
    "start_time": datetime.utcnow().isoformat(),
    "total_rows": 0,
    "total_alerts": 0,
    "kb_matches": 0,
    "activity": {},
    "procs": {}
}


# ── JSON encoder that handles numpy int64/float64/bool ───────────────────────
class _SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            import numpy as np
            if isinstance(obj, np.integer):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.bool_):
                return bool(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
        except ImportError:
            pass
        return super().default(obj)

def _safe_dumps(obj) -> str:
    return json.dumps(obj, cls=_SafeEncoder)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    print(f"[API] Guardian Web Portal ready at http://localhost:8080")
    print(f"[API] Machine ID: {MACHINE_ID}")
    yield

app = FastAPI(title="Guardian", lifespan=lifespan)

# ── Dashboard State Cache ─────────────────────────────────────────────────────
dashboard_state = {
    "procs": {},
    "activityCounts": {},
    "scoreData": [],
    "scoreLabels": [],
    "health": 100,
    "row_count": 0,
    "alert_count": 0
}

def push_event(event: dict):
    """Called by guardian_live.py — serializes numpy types before queuing."""
    
    # Live Caching to support F5 Page Refresh
    if event.get("type") == "verdict":
        pid = str(event.get("pid", "unknown"))
        if pid not in dashboard_state["procs"]:
            dashboard_state["procs"][pid] = {
                "name": event.get("name", pid), 
                "category": event.get("category", "Unknown"), 
                "gpu": 0, "count": 0, "alerts": 0, 
                "first_seen": time.time() * 1000
            }
        
        p_state = dashboard_state["procs"][pid]
        p_state["gpu"] = event.get("gpu_ms", 0)
        p_state["count"] += 1
        p_state["category"] = event.get("category", "Unknown")
        
        is_anomaly = (event.get("score") == -1)
        if is_anomaly:
            p_state["alerts"] += 1

        cat = event.get("category", "Unknown")
        dashboard_state["activityCounts"][cat] = dashboard_state["activityCounts"].get(cat, 0) + 1
        
        dashboard_state["row_count"] += 1
        if is_anomaly:
            dashboard_state["alert_count"] += 1
            
        dashboard_state["health"] = max(0, 100 * (1 - dashboard_state["alert_count"] / max(dashboard_state["row_count"], 1)))

        import datetime
        t = datetime.datetime.fromtimestamp(event.get("ts", time.time())).strftime("%I:%M:%S %p")
        sev = float(event.get("severity", 0))
        if sev > 1.0: sev = 1.0
        plotVal = -max(sev, 0.2) if is_anomaly else max(1.0 - sev, 0.1)
        
        dashboard_state["scoreLabels"].append(t)
        dashboard_state["scoreData"].append(plotVal)
        if len(dashboard_state["scoreLabels"]) > 80:
            dashboard_state["scoreLabels"].pop(0)
            dashboard_state["scoreData"].pop(0)

    try:
        serialized = _safe_dumps(event)
        event_queue.put_nowait(serialized)
    except queue.Full:
        pass  # Dashboard is behind — drop, never block Brain

# ── Pydantic Models ───────────────────────────────────────────────────────────
class RegisterPayload(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class LoginPayload(BaseModel):
    username: str
    password: str

class VerifySignupPayload(BaseModel):
    email: str
    otp_code: str

class VerifyLoginPayload(BaseModel):
    username: str
    otp_code: str

class OTPRequestPayload(BaseModel):
    pid: str
    process_name: str
    exe_path: Optional[str] = None
    machine_id: Optional[str] = None

class OTPApprovePayload(BaseModel):
    otp_code: str
    pid: str

class DirectWhitelistPayload(BaseModel):
    process_name: str
    category: str
    exe_path: Optional[str] = None

class ActionPayload(BaseModel):
    action: str
    pid: str
    process_name: str

class IgnoredPayload(BaseModel):
    pid: str
    process_name: str

class ProcessStatusPayload(BaseModel):
    names: list[str]

class SessionPayload(BaseModel):
    start_time: float
    end_time: float
    total_rows: int
    total_alerts: int
    kb_matches: int
    top_processes: list
    health_score: float
    conclusion_text: str = "Session Completed"

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    if await db.has_any_admin():
        return RedirectResponse("/login")
    return _read_web_file("setup.html")

@app.post("/auth/setup")
async def do_setup(payload: RegisterPayload):
    if await db.has_any_admin():
        raise HTTPException(400, "Setup already complete")
    pw = auth.hash_password(payload.password)
    ok = await db.create_user(payload.username, payload.email, pw, role="admin")
    if not ok:
        raise HTTPException(400, "Username or email already taken")
    return {"ok": True}

@app.post("/auth/register")
async def register(payload: RegisterPayload, request: Request, background_tasks: BackgroundTasks):
    pw = auth.hash_password(payload.password)
    
    # Root user semsem400 constraint
    assigned_role = "pending_admin" if payload.role == "admin" else "user"
    
    ok = await db.create_user(payload.username, payload.email, pw, role=assigned_role, is_verified=0)
    if not ok:
        raise HTTPException(400, "Username or email already taken")
        
    otp = auth.generate_otp()
    expires = auth.make_otp_expiry(minutes=10)
    await db.create_auth_otp(payload.email, otp, "signup", expires)
    
    background_tasks.add_task(auth.send_auth_otp_email, payload.email, otp, "signup")
    
    return {"ok": True, "status": "verification_required", "email": payload.email}

@app.post("/auth/verify-signup")
async def verify_signup(payload: VerifySignupPayload):
    valid = await db.validate_auth_otp(payload.email, payload.otp_code, "signup")
    if not valid:
        raise HTTPException(400, "Invalid or expired verification code")
    
    await db.mark_user_verified(payload.email)
    return {"ok": True, "message": "Email verified successfully"}

@app.post("/auth/login")
async def login(payload: LoginPayload, request: Request, background_tasks: BackgroundTasks):
    user = await db.get_user_by_username(payload.username)
    if not user or not auth.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
        
    if user.get("is_verified", 1) == 0:
        raise HTTPException(403, "Email not verified. Please verify your email first.")
        
    if user["role"] == "pending_admin":
        raise HTTPException(403, "Your administrative account is pending approval from the root admin (semsem400).")
        
    otp = auth.generate_otp()
    expires = auth.make_otp_expiry(minutes=10)
    await db.create_auth_otp(user["email"], otp, "login", expires)
    
    background_tasks.add_task(auth.send_auth_otp_email, user["email"], otp, "login")
    
    return {"ok": True, "status": "otp_required", "email": user["email"]}
