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
    def kill_process():
        try:
            killed_pids = windows_killer.force_kill_tree(int(pid), name)
            if killed_pids:
                status_var.set(f"✓ {name} terminated ({len(killed_pids)} process(es)).")
            else:
                status_var.set(f"✓ {name} terminated (syscall).")
            set_cooldown() # Prevent instantaneous re-alerts before OS cleans up
            root.after(1200, _safe_close)
        except Exception as e:
            status_var.set(f"Kill failed: {e}")

    def suspend_process():
        try:
            import psutil
            psutil.Process(int(pid)).suspend()
            status_var.set(f"⏸ PID {pid} suspended.")
            root.after(1200, _safe_close)
        except ImportError:
            status_var.set("Install psutil for suspend")
        except Exception as e:
            status_var.set(f"Suspend failed: {e}")

    def request_whitelist():
        try:
            import urllib.request, json
            import psutil
            mid = _api.MACHINE_ID if _API_AVAILABLE else "local"
            
            # Fetch full path if achievable
            try:
                exe_path = psutil.Process(int(pid)).exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                exe_path = name
                
            req = urllib.request.Request("http://localhost:8080/whitelist/request", 
                data=json.dumps({"pid": pid, "process_name": name, "exe_path": exe_path, "machine_id": mid}).encode('utf-8'),
                headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req)
            status_var.set(f"✓ Request sent to Admin.")
            set_cooldown() # Wait 5 minutes for admin to respond
            root.after(1400, _safe_close)
        except Exception as e:
            status_var.set(f"Request failed: {e}")

    def leave_process():
        try:
            import urllib.request, json
            mid = _api.MACHINE_ID if _API_AVAILABLE else "local"
            req = urllib.request.Request("http://localhost:8080/ignored", 
                data=json.dumps({"pid": pid, "process_name": name, "machine_id": mid}).encode('utf-8'),
                headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req)
        except Exception:
            pass
        set_cooldown() # 5 minute cooldown
        _safe_close()

    btn_cfg = dict(font=("Segoe UI", 9, "bold"), width=15,
                   relief="flat", cursor="hand2", pady=5)

    tk.Button(btn_frame, text="🗡 Kill",
              bg="#e94560", fg="white", command=kill_process,
              **btn_cfg).pack(side="left", padx=4)
    tk.Button(btn_frame, text="⏸ Suspend",
              bg="#f4a261", fg="white", command=suspend_process,
              **btn_cfg).pack(side="left", padx=4)
    
    btn_frame_bottom = tk.Frame(root, bg="#1a1a2e", pady=5)
    btn_frame_bottom.pack()
    
    tk.Button(btn_frame_bottom, text="🛡 Request Whitelist",
              bg="#06d6a0", fg="#1a1a2e", command=request_whitelist,
              **btn_cfg).pack(side="left", padx=4)
    tk.Button(btn_frame_bottom, text="→ Leave",
              bg="#444", fg="white", command=leave_process,
              **btn_cfg).pack(side="left", padx=4)

    root.mainloop()

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def pick_watch_dir():
    if os.path.isdir(WATCH_DIR) and glob.glob(os.path.join(WATCH_DIR, "gpu_log_*.csv")):
        return WATCH_DIR
    return FALLBACK_DIR

def get_latest_csv(watch_dir):
    files = glob.glob(os.path.join(watch_dir, "gpu_log_*.csv"))
    return max(files, key=os.path.getmtime) if files else None

def activity_icon(cat):
    icons = {
        "Gaming":          MAG  + "🎮 Gaming"    + RST,
        "Compute":         YEL  + "⚙  Compute"   + RST,
        "3D/UI Activity":  CYN  + "🖥  3D/UI"     + RST,
        "Idle":            DIM  + "💤 Idle"       + RST,
    }
    return icons.get(cat, DIM + cat + RST)

def verdict_str(score, severity, confidence, category, aux=None):
    if isinstance(aux, list) and "SUSTAINED_COMPUTE_TRAP" in aux:
         return f"{RED+BOLD}✗ SUSTAINED COMPUTE{RST}"
    if isinstance(aux, list) and "GRACE_WINDOW" in aux:
        return f"{DIM}⏳ GRACE  (learning){RST}"
    if isinstance(aux, list) and "System Whitelisted" in aux:
        return f"{GRN}✓ SYS WL{RST}"
    if isinstance(aux, list) and "Admin Whitelisted" in aux:
        return f"{GRN}✓ ADM WL{RST}"
    if score == -1:
        return f"{RED}✗ ANOMALY  [{severity:.3f}]{RST}"
    if confidence == KnowledgeBank.DEFINITE_SAFE:
        return f"{GRN}✓ KB SAFE{RST}"
    if confidence == KnowledgeBank.PROBABLE_SAFE:
        return f"{CYN}~ PROBABLE SAFE{RST}"
    return f"{YEL}? ML OK  [{severity:.3f}]{RST}"

def print_header(watch_dir, csv_path):
    print(f"\n{BOLD}{'═'*80}{RST}")
    print(f"{BOLD}  GUARDIAN  —  Live GPU Monitor{RST}")
    print(f"  Watching : {DIM}{csv_path or watch_dir}{RST}")
    print(f"{BOLD}{'─'*80}{RST}")
    print(f"  {'PID':<8} {'PROCESS':<24} {'Activity':<16} "
          f"{'Pwr(W)':>6} {'Mem(MB)':>8} {'GPU(ms)':>7} {'Pkts':>7}  Verdict")

def whitelist_tree(tgt_name, exe_path, brain):
    """Add process + children to both the in-memory whitelist and KB."""
    brain.whitelist.add_admin_live(tgt_name)
    brain.knowledge.add_admin_whitelist(tgt_name)
    count = 1
    try:
        import psutil
        for p in psutil.process_iter(['name', 'exe']):
            if p.info['name'] == tgt_name or (exe_path and p.info['exe'] == exe_path):
                if p.info['name'] and p.info['name'] != tgt_name:
                    brain.whitelist.add_admin_live(p.info['name'])
                    brain.knowledge.add_admin_whitelist(p.info['name'])
                    count += 1
                try:
                    for child in p.children(recursive=True):
                        try:
                            cname = child.name()
                            if cname and cname != tgt_name:
                                brain.whitelist.add_admin_live(cname)
                                brain.knowledge.add_admin_whitelist(cname)
                                count += 1
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except:
                    pass
    except Exception as e:
        print(f"Error whitelisting tree: {e}")
    return count

# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
def print_summary(stats, row_count, alert_count, start_time, brain):
    elapsed = time.time() - start_time
    health  = 100 * (1 - alert_count / max(row_count, 1))

    print(f"\n\n{BOLD}{'═'*66}{RST}")
    print(f"{BOLD}  SESSION REPORT  —  {time.strftime('%H:%M:%S')}{RST}")
    print(f"{'═'*66}")

    # ── Overview ─────────────────────────────────────────────────────────
    mins, secs = divmod(int(elapsed), 60)
    print(f"\n  {'Duration':<22} {mins}m {secs}s")
    print(f"  {'Total rows processed':<22} {row_count:,}")
    print(f"  {'Anomalies detected':<22} {alert_count:,}")
    print(f"  {'KB matches':<22} {stats['kb_matches']:,}")
    health_col = GRN if health > 80 else YEL if health > 60 else RED
    bar = "█" * int(health/5) + "░" * (20 - int(health/5))
    print(f"  {'System health':<22} {health_col}{health:.1f}%  [{bar}]{RST}")

    # ── Activity breakdown ────────────────────────────────────────────────
    print(f"\n  {BOLD}Activity Breakdown{RST}")
    print(f"  {'─'*40}")
    total_act = sum(stats['activity'].values()) or 1
    for act, cnt in sorted(stats['activity'].items(), key=lambda x: -x[1]):
        pct  = 100 * cnt / total_act
        bar2 = "█" * int(pct / 4)
        print(f"  {act:<22}  {pct:>5.1f}%  {bar2}")

    # ── Top processes ─────────────────────────────────────────────────────
    print(f"\n  {BOLD}Top Processes by Event Count{RST}")
    print(f"  {'─'*60}")
    print(f"  {'Process':<30} {'Events':>7} {'Alerts':>7} {'Avg GPU ms':>10}")
    print(f"  {'─'*60}")
    top = sorted(stats['procs'].items(), key=lambda x: -x[1]['events'])[:10]
    for name, s in top:
        avg_gpu = s['gpu_sum'] / max(s['events'], 1)
        alert_col = RED if s['alerts'] > 0 else RST
        print(f"  {name[:29]:<30} {s['events']:>7,} "
              f"{alert_col}{s['alerts']:>7,}{RST} "
              f"{avg_gpu:>10.2f}")

    # ── Scoring system explanation ─────────────────────────────────────────
    print(f"\n  {BOLD}Scoring System{RST}")
    print(f"  {'─'*60}")
    print(f"  IsoForest severity → safe if ≥ -0.40   anomaly if < -0.70")
    print(f"  Ambiguous zone       -0.70 to -0.40  → Vault check + Ghost/LOF")
    print(f"  KB radius check      normalized dist  → DEFINITE / PROBABLE / UNKNOWN")
    print(f"  Tier 1 heuristic     pkts>200 & ms<1  → instant SUSPICIOUS_COPY flag")

    # ── KB state ──────────────────────────────────────────────────────────
    print(f"\n  {BOLD}Knowledge Bank State{RST}")
    print(f"  {'─'*40}")
    for sig in brain.knowledge.known_signatures:
        name   = sig.get('name', sig.get('label', 'unknown'))[:35]
        hits   = sig.get('hit_count', 0)
        radius = sig.get('radius', 0)
        print(f"  {name:<36}  hits={hits:>5}  radius={radius:>8.1f}")

    print(f"\n{'═'*66}\n")
    
    # Save to API
    try:
        if _API_AVAILABLE:
            import urllib.request, json
            top_procs = [{'name': k, 'events': v['events']} for k,v in top]
            data = {
                "start_time": start_time,
                "end_time": time.time(),
                "total_rows": row_count,
                "total_alerts": alert_count,
                "kb_matches": stats.get('kb_matches', 0),
                "top_processes": top_procs,
                "health_score": health,
                "conclusion_text": "Session Completed via Keyboard Interrupt"
            }
            req = urllib.request.Request("http://localhost:8080/sessions", 
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2.0)
            print(f"{DIM}Session history persisted to Web Dashboard.{RST}")
    except Exception as e:
        print(f"{DIM}Could not save session to API: {e}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    watch_dir = pick_watch_dir()
    print(f"\n[Live] Watching: {BOLD}{watch_dir}{RST}")
    print(f"[Live] Loading brain (this takes a few seconds)...")

    brain = GuardianBrain()
    brain.train_initial(watch_dir)

    # Start Web API in background thread
    if _API_AVAILABLE:
        def _run_api():
            _uvicorn.run("guardian_api:app", host="0.0.0.0", port=8080, log_level="warning")
        api_thread = threading.Thread(target=_run_api, daemon=True)
        api_thread.start()
        print(f"[Live] Web dashboard available at {BOLD}http://localhost:8080{RST}")

    tracker = PIDTracker(max_history=60)
    sustained_detector = SustainedAttackDetector()
    last_sustained_check = time.time()

    # Session stats
    stats = {
        'activity':  collections.Counter(),
        'procs':     collections.defaultdict(lambda: {'events': 0, 'alerts': 0, 'gpu_sum': 0.0}),
        'kb_matches': 0,
    }

    latest      = None
    file_handle = None
    row_count   = 0
    alert_count = 0
    start_time  = time.time()

    print_header(watch_dir, None)
    print(f"  {DIM}Waiting for GPU logger CSV...{RST}\n")

    try:
        while True:
            new_latest = get_latest_csv(watch_dir)

            if new_latest != latest:
                if file_handle:
                    file_handle.close()
                latest = new_latest
                if latest:
                    file_handle = open(latest, 'r', encoding='utf-8', errors='replace')
                    file_handle.seek(0, 2)
                    print_header(watch_dir, latest)

            if not file_handle:
                time.sleep(0.5)
                continue

            for raw in file_handle.readlines():
                raw = raw.strip()
                if not raw or raw.startswith("Timestamp"):
                    continue

                data = parse_line(raw)
                if not data:
                    continue

                row_count += 1
                category   = classify_activity(data)
                vec        = [data[c] for c in brain.feature_cols]
                name       = data.get('NAME', 'Unknown')
                pid        = str(data.get('PID', '?'))

                score, severity, aux = brain.predict_hybrid(
                    vec, process_name=name
                )
                confidence, _        = brain.knowledge.is_known(
                    vec, name_override=name
                )
