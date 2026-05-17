"""
guardian_live.py  —  Real-Time GPU Activity Monitor + Alert Popup
==================================================================
Streams every row from the CURRENT active GPU logger CSV.
Shows live formatted readings + brain verdict per process.
Pops up a tkinter alert window for every confirmed anomaly.

Usage:
    python guardian_live.py
"""

import os, sys, glob, time, threading, subprocess, collections, windows_killer
import tkinter as tk
from tkinter import ttk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian_brain import (
    GuardianBrain, KnowledgeBank, classify_activity, parse_line
)
from pid_tracker import PIDTracker, SustainedAttackDetector
# whitelist_system.is_system_whitelisted is now handled inside GuardianBrain.whitelist

# ── Optional Web Dashboard (graceful degradation if FastAPI not installed) ──
try:
    import guardian_api as _api
    import uvicorn as _uvicorn
    _API_AVAILABLE = True
except ImportError:
    _API_AVAILABLE = False
    print("[Live] Web dashboard unavailable (install fastapi & uvicorn to enable)")

# ── Watch dirs ────────────────────────────────────────────────────────────────
HERE          = os.path.dirname(os.path.abspath(__file__))
WATCH_DIR     = os.path.join(HERE, "build", "Release")
FALLBACK_DIR  = HERE

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED  = "\033[91m"; YEL  = "\033[93m"; GRN  = "\033[92m"
CYN  = "\033[96m"; MAG  = "\033[95m"; DIM  = "\033[2m"
BOLD = "\033[1m";  RST  = "\033[0m"

import queue

# ── Alert popup dedup & queue (strictly sequential popups) ───────────────────
_alerted_pids  = {}         # {name: timestamp_of_ignore} for 5-minute cooldown
_popup_pending = set()      # names currently in queue or showing
_popup_lock    = threading.Lock()
_popup_queue   = queue.Queue()

def _popup_worker():
    while True:
        try:
            args = _popup_queue.get()
            _show_popup_sync(*args)
        except Exception as e:
            print(f"Popup worker error: {e}")

threading.Thread(target=_popup_worker, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT POPUP WINDOW
# ═══════════════════════════════════════════════════════════════════════════════
def launch_alert_popup(data, vec, severity, category, brain):
    """Enqueues a popup if the process is not on cooldown or already queued."""
    name = data.get('NAME', 'Unknown')
    
    with _popup_lock:
        if name in _popup_pending:
            return  # already waiting for user input
        if name in _alerted_pids:
            if time.time() - _alerted_pids[name] < 300: # 5 min cooldown
                return
            else:
                del _alerted_pids[name] # Expired, let it through
                
        _popup_pending.add(name)
        
    _popup_queue.put((data, vec, severity, category, brain))

def _show_popup_sync(data, vec, severity, category, brain):
    pid  = str(data.get('PID', '?'))
    name = data.get('NAME', 'Unknown')
    gpu  = data.get('GPU_TIME_MS', 0)
    pkts = data.get('GPU_PACKET_COUNT', 0)

    root = tk.Tk()
    root.configure(bg="#1a1a2e")
    root.resizable(False, False)
    root.attributes("-topmost", True)
    root.overrideredirect(True)   # ← removes minimize/maximize/close bar

    # ── Custom drag handle (replaces OS title bar) ───────────────────
    drag = tk.Frame(root, bg="#e94560", cursor="fleur")
    drag.pack(fill="x")
    _drag = {"x": 0, "y": 0}
    def _start_drag(e): _drag["x"] = e.x; _drag["y"] = e.y
    def _do_drag(e):
        dx = e.x - _drag["x"]; dy = e.y - _drag["y"]
        root.geometry(f"+{root.winfo_x()+dx}+{root.winfo_y()+dy}")
    drag.bind("<Button-1>", _start_drag)
    drag.bind("<B1-Motion>", _do_drag)
    tk.Label(drag, text="⚠  GUARDIAN  —  ANOMALY DETECTED",
             font=("Segoe UI", 12, "bold"),
             bg="#e94560", fg="white", pady=8).pack()

    # ── Center window on screen ──────────────────────────────────────
    root.update_idletasks()
    sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
    root.geometry(f"+{(sw-360)//2}+{(sh-420)//2}")

    # ── Info panel ──────────────────────────────────────────────────
    info = tk.Frame(root, bg="#16213e", padx=20, pady=15)
    info.pack(fill="x", padx=10, pady=(10, 0))

    def row(label, value, fg="#e0e0e0"):
        f = tk.Frame(info, bg="#16213e")
        f.pack(fill="x", pady=2)
        tk.Label(f, text=f"{label:<18}", font=("Consolas", 10),
                 bg="#16213e", fg="#888").pack(side="left")
        tk.Label(f, text=value, font=("Consolas", 10, "bold"),
                 bg="#16213e", fg=fg).pack(side="left")

    row("Process",   name,               "#ff6b6b")
    row("PID",       pid,                "#ffd166")
    row("Activity",  category,           "#06d6a0")
    row("GPU time",  f"{gpu:.2f} ms")
    row("Packets",   f"{int(pkts)}")
    row("Severity",  f"{severity:.4f}",  "#ff6b6b")

    # ── Score bar ───────────────────────────────────────────────────
    sev_norm  = max(0, min(1, (severity + 1.0)))
    bar_frame = tk.Frame(root, bg="#1a1a2e", pady=5)
    bar_frame.pack(fill="x", padx=15)
    tk.Label(bar_frame, text="Threat level:", font=("Segoe UI", 9),
             bg="#1a1a2e", fg="#888").pack(anchor="w")
    canvas = tk.Canvas(bar_frame, height=12, bg="#0f3460",
                       highlightthickness=0, width=330)
    canvas.pack(fill="x")
    canvas.update()
    w = canvas.winfo_width() or 330
    fill_w = int(w * (1 - sev_norm))
    canvas.create_rectangle(0, 0, fill_w, 12, fill="#e94560", outline="")

    # ── Status label ─────────────────────────────────────────────────
    status_var = tk.StringVar(value="Choose an action:")
    tk.Label(root, textvariable=status_var, font=("Segoe UI", 9),
             bg="#1a1a2e", fg="#aaa").pack(pady=(8, 0))

    # ── Action buttons ───────────────────────────────────────────────
    btn_frame = tk.Frame(root, bg="#1a1a2e", pady=10)
    btn_frame.pack()

    def set_cooldown():
        with _popup_lock:
            _alerted_pids[name] = time.time()

    def _safe_close():
        with _popup_lock:
            _popup_pending.discard(name)
        try:
            root.quit(); root.destroy()
        except:
            pass
