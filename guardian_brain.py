import time
import os
import glob
import sqlite3
import threading
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime
import warnings
import atexit
import gzip
import json
import queue
import collections
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EmpiricalCovariance

warnings.filterwarnings('ignore')

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE       = os.path.dirname(os.path.abspath(__file__))
LOG_DIR     = _HERE
MODEL_PATH  = os.path.join(_HERE, "brain_state.pkg")
VAULT_PATH  = os.path.join(_HERE, "guardian_vault.jsonl.gz")
KB_PATH     = os.path.join(_HERE, "knowledge_bank.json")
ARCHIVE_PATH = os.path.join(_HERE, "guardian_archive.npz")
BUILD_RELEASE_DIR = os.path.join(_HERE, "build", "Release")

# ── Constants ─────────────────────────────────────────────────────────────────
ANOMALY_SCORE_THRESHOLD = -0.55   # score_samples() threshold (not predict())
RETRAIN_INTERVAL        = 200     # events between IsoForest retrains
SAVE_INTERVAL           = 200     # events between periodic brain saves
GRACE_WINDOW            = 100     # events per process before detection starts
SLIDE_WINDOW_SIZE       = 10      # rolling window for sustained gate
SLIDE_WINDOW_THRESHOLD  = 3       # anomalies in window to trigger alert
NET_WARMUP_EVENTS       = 15      # events to ramp network feature weight 0→1
NET_ACTIVATION_THRESH   = 500.0   # NET_TX/RX must exceed this to activate gate
VAULT_MAX_ENTRIES       = 50_000  # hard cap on vault size
KB_CANDIDATE_HITS       = 30      # hits before promoting to KB signature
KB_CANDIDATE_AGE        = 60.0    # seconds before promoting to KB signature
DB_WATCH_INTERVAL       = 2.0     # seconds between whitelist DB polls

# =============================================================================
# WHITELIST MANAGER — hot-reloadable, DB-backed, O(1) lookup
# =============================================================================
class WhitelistManager:
    """Maintains two in-memory sets for O(1) lookup.

    system_wl  : loaded from whitelist_system.py hardcoded set (static, never
                 written to DB — these are OS-level processes)
    admin_wl   : loaded from guardian.db whitelist_log table, reloaded every
                 DB_WATCH_INTERVAL seconds by a background watcher thread.

    Both sets are checked BEFORE any ML runs.
    """

    def __init__(self, db_path: str):
        self.db_path    = db_path
        self.system_wl: set[str] = set()
        self.admin_wl:  set[str] = set()
        self._lock      = threading.RLock()
        self._running   = True

        # Load static system whitelist from whitelist_system.py
        self._load_system_whitelist()
        # Initial DB load
        self._reload_admin_from_db()
        # Start background watcher
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
        self._watcher.start()

    def _load_system_whitelist(self):
        try:
            from whitelist_system import SYSTEM_WHITELIST
            with self._lock:
                self.system_wl = {n.lower() for n in SYSTEM_WHITELIST}
            print(f"[WL] System whitelist loaded: {len(self.system_wl)} entries.")
        except ImportError:
            print("[WL] whitelist_system.py not found — system whitelist empty.")

    def _reload_admin_from_db(self):
        if not os.path.exists(self.db_path):
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT DISTINCT process_name FROM whitelist_log")
                rows = c.fetchall()
            new_set = {r[0].lower() for r in rows}
            with self._lock:
                self.admin_wl = new_set
        except Exception as e:
            print(f"[WL] DB reload failed: {e}")

    def _watch_loop(self):
        while self._running:
            time.sleep(DB_WATCH_INTERVAL)
            self._reload_admin_from_db()

    def is_system(self, name: str) -> bool:
        # Security fix: delegate to is_system_whitelisted() which enforces
        # full path verification — prevents disguised binaries from bypassing the AI.
        from whitelist_system import is_system_whitelisted
        return is_system_whitelisted(name)

    def is_admin(self, name: str) -> bool:
        basename = name.replace('\\', '/').split('/')[-1].lower().strip()
        with self._lock:
            return basename in self.admin_wl

    def add_admin_live(self, name: str):
        """Instantly add to in-memory admin set (DB write is caller's responsibility)."""
        with self._lock:
            self.admin_wl.add(name.lower())

    def revoke_admin_live(self, name: str):
        with self._lock:
            self.admin_wl.discard(name.lower())

    def stop(self):
        self._running = False


# =============================================================================
# NETWORK FEATURE GATE — per-process 3-phase activation
# =============================================================================
class NetworkGate:
    """Per-process network feature weight gate.

    Phase 0 — SILENT:   NET below threshold → weight=0.0 (excluded)
    Phase 1 — WARMING:  NET first exceeds threshold → ramp 0→1 over N events
    Phase 2 — ACTIVE:   warmup complete → weight=1.0 (full inclusion)

    Prevents net spikes (downloads, video, first-connect bursts) from
    immediately contaminating the IsoForest scores built on net=0 data.
    """

    SILENT  = 0
    WARMING = 1
    ACTIVE  = 2

    def __init__(self):
        # {process_name: {'phase': int, 'warmup_count': int}}
        self._state: dict[str, dict] = {}

    def get_weight(self, name: str, net_tx: float, net_rx: float) -> float:
        """Return the current network blending weight for this process (0.0–1.0)."""
        s = self._state.setdefault(name, {'phase': self.SILENT, 'warmup': 0})

        active = max(net_tx, net_rx) > NET_ACTIVATION_THRESH

        if s['phase'] == self.SILENT:
            if active:
                s['phase']   = self.WARMING
                s['warmup']  = 0
            return 0.0

        if s['phase'] == self.WARMING:
            s['warmup'] += 1
            weight = s['warmup'] / NET_WARMUP_EVENTS
            if s['warmup'] >= NET_WARMUP_EVENTS:
                s['phase'] = self.ACTIVE
            return min(weight, 1.0)

        # ACTIVE
        # If net drops back to zero for a while, reset to SILENT
        if not active:
            s['phase']  = self.SILENT
            s['warmup'] = 0
            return 0.0
        return 1.0

    def apply(self, name: str, vec: list[float]) -> list[float]:
        """Return vec with NET_TX (idx 4) and NET_RX (idx 5) weighted."""
        net_tx, net_rx = vec[4], vec[5]
        w = self.get_weight(name, net_tx, net_rx)
        blended = list(vec)
        blended[4] = net_tx * w
        blended[5] = net_rx * w
        return blended


# =============================================================================
# KNOWLEDGE BANK — Welford centroid + Mahalanobis distance
# =============================================================================
class KnowledgeBank:
    """Adaptive signature store.

    Each signature: centroid (Welford mean) + adaptive radius.
    Distance check: Mahalanobis (per-class covariance) so MEM_MB doesn't
    dominate the Euclidean magnitude.  Falls back to normalized Euclidean
    if covariance not yet available.
    """

    DEFINITE_SAFE = "DEFINITE_SAFE"
    PROBABLE_SAFE = "PROBABLE_SAFE"
    UNKNOWN       = "UNKNOWN"

    CANDIDATE_PROMOTE_HITS = KB_CANDIDATE_HITS
    CANDIDATE_BUCKET_SIZE  = 0.15

    def __init__(self, kb_path=KB_PATH):
        self.kb_path          = kb_path
        self.known_signatures = []
        self._candidates      = {}
        self._candidates      = {}
        # Single global covariance inverse for Mahalanobis (rebuilt after retrain)
        self._cov_inv: np.ndarray = None
        self.load()
        self._load_admin_whitelist_from_db()

    # ── Persistence ───────────────────────────────────────────────────────────
    def load(self):
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, 'r') as f:
                    self.known_signatures = json.load(f)
                print(f"[KB] Loaded {len(self.known_signatures)} signatures.")
            except:
                self.known_signatures = []

    def save(self):
        try:
            with open(self.kb_path, 'w') as f:
                json.dump(self.known_signatures, f, indent=2)
        except Exception as e:
            print(f"[KB] Save failed: {e}")

    # ── DB whitelist sync ─────────────────────────────────────────────────────
    def _load_admin_whitelist_from_db(self):
        db_path = os.path.join(_HERE, "guardian.db")
        if not os.path.exists(db_path):
            return
        try:
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT DISTINCT process_name FROM whitelist_log")
                rows = c.fetchall()
            # Build set of already-present admin override names to avoid duplicates
            existing_overrides = {
                sig.get('name') for sig in self.known_signatures
                if sig.get('_is_admin_override')
            }
            added = 0
            for row in rows:
                name = row['process_name']
                if name in existing_overrides or name == "Unknown":
                    continue
                self.known_signatures.append({
                    "name": name, "label": "Admin Whitelisted",
                    "vector": [0.0] * 6, "radius": 9999.0,
                    "hit_count": 1, "_is_admin_override": True
                })
                existing_overrides.add(name)
                added += 1
            if added:
                print(f"[KB] Loaded {added} admin whitelists from DB.")
        except Exception as e:
            print(f"[KB] DB whitelist load failed: {e}")
