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

