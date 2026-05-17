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

@app.post("/auth/verify-login")
async def verify_login(payload: VerifyLoginPayload, request: Request):
    user = await db.get_user_by_username(payload.username)
    if not user:
        raise HTTPException(401, "Invalid user")
        
    valid = await db.validate_auth_otp(user["email"], payload.otp_code, "login")
    if not valid:
        raise HTTPException(401, "Invalid or expired login code")
        
    token = auth.create_session_token()
    expires = auth.make_expiry(days=7)
    await db.create_web_session(user["id"], token, expires, ip=request.client.host)
    resp = JSONResponse({"ok": True, "role": user["role"], "username": user["username"]})
    resp.set_cookie("guardian_token", token, httponly=True, samesite="strict", max_age=60*60*24*7)
    return resp

@app.post("/auth/logout")
async def logout(guardian_token: str = Cookie(default=None)):
    if guardian_token:
        await db.delete_session(guardian_token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("guardian_token")
    return resp

@app.get("/auth/me")
async def me(user=Depends(auth.get_current_user)):
    if not user:
        return {"role": "guest"}
    return {"username": user["username"], "role": user["role"], "email": user.get("email")}

@app.get("/users")
async def get_users(user=Depends(auth.require_admin)):
    async with db.aiosqlite.connect(db.DB_PATH) as conn:
        conn.row_factory = db.aiosqlite.Row
        async with conn.execute("SELECT id, username, email, role, machine_id, created_at FROM users") as c:
            rows = await c.fetchall()
            return [dict(r) for r in rows]

@app.post("/users/{user_id}/approve")
async def approve_new_admin(user_id: int, user=Depends(auth.require_admin)):
    if user["username"].lower() != "semsem400":
        raise HTTPException(403, "Only the root administrator (semsem400) can approve new admins.")
    async with db.aiosqlite.connect(db.DB_PATH) as conn:
        await conn.execute("UPDATE users SET role='admin' WHERE id=? AND role='pending_admin'", (user_id,))
        await conn.commit()
    return {"ok": True}

@app.delete("/users/{user_id}")
async def delete_user_endpoint(user_id: int, user=Depends(auth.require_admin)):
    if user["username"].lower() != "semsem400":
        raise HTTPException(403, "Only the root administrator (semsem400) can delete users.")
    await db.delete_user(user_id)
    return {"ok": True}


# ── OTP Whitelist Routes ──────────────────────────────────────────────────────
@app.post("/whitelist/request")
async def request_whitelist(payload: OTPRequestPayload, request: Request, background_tasks: BackgroundTasks, user=Depends(auth.get_current_user)):
    otp = auth.generate_otp()
    expires = auth.make_otp_expiry(minutes=10)
    machine_id = payload.machine_id or MACHINE_ID
    requester_name = user["username"] if user else "Local System Pop-up"
    
    await db.create_otp_request(
        payload.pid, payload.process_name, otp, expires,
        machine_id=machine_id, exe_path=payload.exe_path,
        requester=requester_name
    )
    
    # Broadcast to admin dashboards instantly
    push_event({
        "type": "whitelist_requested",
        "pid": payload.pid,
        "name": payload.process_name,
        "machine_id": machine_id,
        "otp": otp,
        "ts": time.time()
    })

    async with db.aiosqlite.connect(db.DB_PATH) as conn:
        conn.row_factory = db.aiosqlite.Row
        async with conn.execute("SELECT email FROM users WHERE role='admin' AND is_active=1") as c:
            admins = await c.fetchall()
            
    for admin in admins:
        background_tasks.add_task(auth.send_otp_email, admin["email"], otp, payload.process_name, payload.pid)
        
    return {"ok": True, "message": "OTP sent to admin"}

@app.post("/whitelist/approve")
async def approve_whitelist(payload: OTPApprovePayload, user=Depends(auth.require_admin)):
    row = await db.validate_and_approve_otp(payload.otp_code, payload.pid, user["user_id"])
    if not row:
        raise HTTPException(400, "Invalid or expired OTP code")
        
    try:
        action_queue.put_nowait({
            "action": "approve_whitelist",
            "pid": row["pid"],
            "name": row["process_name"],
            "exe_path": row.get("exe_path")
        })
    except queue.Full:
        pass
        
    return {"ok": True, "process": row["process_name"], "pid": row["pid"]}

@app.get("/whitelist/pending")
async def get_pending(user=Depends(auth.require_admin)):
    return await db.get_pending_otps()

@app.delete("/whitelist/pending/{otp_code}")
async def reject_whitelist(otp_code: str, user=Depends(auth.require_admin)):
    async with db.aiosqlite.connect(db.DB_PATH) as conn:
        await conn.execute("DELETE FROM otp_requests WHERE otp_code=?", (otp_code,))
        await conn.commit()
    return {"ok": True}

@app.delete("/whitelist/pending-by-pid/{pid}")
async def reject_whitelist_by_pid(pid: str, user=Depends(auth.require_admin)):
    """Fallback: delete a pending OTP request by PID (used when otp_code onclick is broken)."""
    async with db.aiosqlite.connect(db.DB_PATH) as conn:
        await conn.execute("DELETE FROM otp_requests WHERE pid=?", (pid,))
        await conn.commit()
    return {"ok": True}

@app.post("/whitelist/direct")
async def direct_whitelist(payload: DirectWhitelistPayload, user=Depends(auth.require_admin)):
    """Admin feature: instantly whitelist a process without OTP."""
    await db.create_whitelist_log(payload.process_name, user["user_id"], payload.exe_path)
    try:
        action_queue.put_nowait({
            "action": "add_whitelist",
            "pid": "0",
            "name": payload.process_name,
            "exe_path": payload.exe_path,
            "requested_by": user["username"]
        })
    except queue.Full:
        pass
    return {"ok": True, "message": f"{payload.process_name} whitelisted automatically."}

@app.get("/whitelist")
async def get_whitelist(user=Depends(auth.require_admin)):
    return await db.get_whitelist_log()

@app.delete("/whitelist/{log_id}")
async def revoke_whitelist(log_id: int, user=Depends(auth.require_admin)):
    name = await db.delete_whitelist_log(log_id)
    if name:
        try:
            action_queue.put_nowait({
                "action": "revoke_whitelist",
                "pid": "0",
                "name": name,
                "requested_by": user["username"]
            })
        except queue.Full:
            pass
    return {"ok": True, "message": "Whitelist revoked."}

# ── Remote Actions & Ignored Routes ───────────────────────────────────────────
@app.post("/action")
async def perform_action(payload: ActionPayload, user=Depends(auth.require_admin)):
    """Admin dashboard sends kill, suspend, or leave commands here."""
    
    # ── Page-Fault Architecture: Immediate Local Execution ──
    if payload.action == "kill":
        result = guardian_actions.execute_kill(payload.pid, payload.process_name)
        return {"ok": result["status"] == "success", "message": result["message"]}
    elif payload.action == "suspend":
        result = guardian_actions.execute_suspend(payload.pid, payload.process_name)
        return {"ok": result["status"] == "success", "message": result["message"]}
        
    # Legacy Queue fallback for leave/whitelist
    try:
        action_queue.put_nowait({
            "action": payload.action,
            "pid": payload.pid,
            "name": payload.process_name,
            "requested_by": user["username"]
        })
        return {"ok": True, "message": f"{payload.action} command queued for {payload.process_name}"}
    except queue.Full:
        raise HTTPException(500, "Local PC action queue is full")

@app.post("/ignored")
async def add_ignored(payload: IgnoredPayload, request: Request):
    if request.client.host not in ["127.0.0.1", "localhost", "::1"]:
        raise HTTPException(status_code=403, detail="Remote submission denied")
    # Public endpoint called by the popup when user clicks "Leave"
    await db.log_ignored_process(payload.pid, payload.process_name)
    try:
        action_queue.put_nowait({
            "action": "leave",
            "pid": payload.pid,
            "name": payload.process_name,
            "requested_by": "User"
        })
    except queue.Full:
        pass
    return {"ok": True}

@app.delete("/ignored/{log_id}")
async def flush_ignored(log_id: int, user=Depends(auth.require_admin)):
    await db.delete_ignored_process(log_id)
    return {"ok": True}

@app.post("/processes/status")
async def check_process_status(payload: ProcessStatusPayload, user=Depends(auth.require_admin)):
    import psutil
    import os
    active = set()
    targets = set([os.path.basename(n.replace('\\', '/')).lower() for n in payload.names])
    for p in psutil.process_iter(['name']):
        if p.info['name'] and p.info['name'].lower() in targets:
            active.add(p.info['name'].lower())
    return {"active": list(active)}

@app.get("/dashboard/state")
async def get_dashboard_state(user=Depends(auth.require_login)):
    return dashboard_state

@app.get("/ignored")
async def get_ignored(user=Depends(auth.require_admin)):
    return await db.get_ignored_processes()

@app.post("/api/shutdown")
async def shutdown_system(request: Request, _=Depends(auth.require_local_api_key)):
    if request.client.host not in ["127.0.0.1", "localhost", "::1"]:
        raise HTTPException(status_code=403, detail="Remote shutdown denied")
    """Triggered by Stop_Guardian.bat to gracefully close Python brain and save history."""
    import _thread
    _thread.interrupt_main()
    return {"ok": True}


# ── Session History Routes ─────────────────────────────────────────────────────
@app.post("/sessions")
async def save_session(payload: SessionPayload, _=Depends(auth.require_local_api_key)):
    from datetime import datetime
    await db.save_session_event(
        start_time=datetime.fromtimestamp(payload.start_time),
        end_time=datetime.fromtimestamp(payload.end_time),
        total_rows=payload.total_rows,
        total_alerts=payload.total_alerts,
        kb_matches=payload.kb_matches,
        top_processes=payload.top_processes,
        conclusion_text=payload.conclusion_text,
        health_score=payload.health_score,
        user_id=None
    )
    return {"ok": True}
@app.get("/sessions")
async def get_sessions(user=Depends(auth.get_current_user)):
    if user and user.get("role") == "admin":
        return await db.get_session_history(machine_id=None, limit=50)
    return await db.get_session_history(machine_id=MACHINE_ID, limit=20)

@app.get("/api/machines")
async def get_machines(user=Depends(auth.get_current_user)):
    db_machines = await db.get_all_machines()
    offline = [m for m in db_machines if m != MACHINE_ID]
    return {"active": [{"id": MACHINE_ID, "status": "ONLINE"}], 
            "offline": [{"id": m, "status": "OFFLINE"} for m in offline]}

@app.get("/api/sessions/{session_id}")
async def get_session_data(session_id: int, user=Depends(auth.get_current_user)):
    data = await db.get_session_by_id(session_id)
    if not data:
        raise HTTPException(404, "Session not found")
    return data

@app.get("/session/{session_id}", response_class=HTMLResponse)
async def view_session_page(session_id: int):
    return _read_web_file("session.html")

@app.get("/sessions/current")
async def get_current_session(user=Depends(auth.get_current_user)):
    return {**session_stats, "machine_id": MACHINE_ID}


# ── WebSocket Live Stream ─────────────────────────────────────────────────────
@app.websocket("/ws/stream")
async def ws_stream(ws: WebSocket):
    # Security: Require valid admin token before opening the stream
    token = ws.cookies.get("guardian_token")
    if not token or not await db.get_session_by_token(token):
        await ws.close(code=1008)
        return
    await ws.accept()
    with _client_lock:
        connected_clients.append(ws)
    ping_counter = 0
    try:
        while True:
            # Batch-drain up to 50 queued events and send as one JSON array frame
            batch = []
            for _ in range(50):
                try:
                    batch.append(event_queue.get_nowait())
                except queue.Empty:
                    break

            if batch:
                # One WS send for all events — eliminates per-event overhead
                await ws.send_text('[' + ','.join(batch) + ']')
                ping_counter = 0
            else:
                await asyncio.sleep(0.05)  # 50ms idle poll
                ping_counter += 1
                # Ping every ~3 seconds (60 × 50ms) to keep connection alive
                if ping_counter >= 60:
                    ping_counter = 0
                    try:
                        await ws.send_text('[{"type":"ping"}]')
                    except Exception:
                        break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        with _client_lock:
            if ws in connected_clients:
                connected_clients.remove(ws)


# ── Serve Dashboard HTML ──────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard(guardian_token: str = Cookie(default=None)):
    if not await db.has_any_admin():
        return RedirectResponse("/setup")
    return _read_web_file("index.html")

@app.get("/home", response_class=HTMLResponse)
async def home_page():
    return _read_web_file("home.html")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return _read_web_file("login.html")

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    return _read_web_file("register.html")


# ── HTML Helper ───────────────────────────────────────────────────────────────
def _read_web_file(name: str) -> str:
    path = os.path.join(HERE, "guardian_web", name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return f"<h1>File not found: {name}</h1>"


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("guardian_api:app", host="0.0.0.0", port=8080, reload=False)
