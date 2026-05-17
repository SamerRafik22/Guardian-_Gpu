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
        def add_admin_whitelist(self, name: str):
        # Dedup: skip if already present as admin override
        if any(s.get('_is_admin_override') and s.get('name') == name
               for s in self.known_signatures):
            return
        self.known_signatures.append({
            "label": "ADMIN_WHITELIST", "name": name,
            "vector": [0.0] * 6, "radius": 9999.0,
            "hit_count": 1, "_is_admin_override": True
        })


    def revoke_admin_whitelist(self, name: str):
        self.known_signatures = [
            s for s in self.known_signatures
            if not (s.get('_is_admin_override') and s.get('name') == name)
        ]

    # ── Covariance update (called after IsoForest retrain) ───────────────────
    def update_covariance(self, data: np.ndarray):
        """Fit a covariance inverse for Mahalanobis distance in `is_known`."""
        if data is None or len(data) < 10:
            return
        try:
            n_features = data.shape[1]
            cov = EmpiricalCovariance().fit(data)
            self._cov_inv = cov.precision_  # = Σ⁻¹
        except Exception:
            pass

    def _mahalanobis(self, x: np.ndarray, ref: np.ndarray) -> float:
        """Mahalanobis distance; falls back to normalized Euclidean."""
        prec = self._cov_inv
        if prec is not None:
            try:
                diff = x - ref
                dist = float(np.sqrt(diff @ prec @ diff))
                return dist
            except Exception:
                pass
        # Fallback: normalized Euclidean
        raw_d  = np.linalg.norm(x - ref)
        ref_mag = max(np.linalg.norm(ref), 1.0)
        return raw_d / ref_mag

    # ── Core lookup ───────────────────────────────────────────────────────────
    def is_known(self, vector, name_override: str = None):
        if name_override:
            for sig in self.known_signatures:
                if sig.get('_is_admin_override') and sig.get('name') == name_override:
                    return self.DEFINITE_SAFE, "Admin Whitelisted"

        if not self.known_signatures:
            return self.UNKNOWN, None

        try:
            vec = np.array(vector, dtype=float)
            best_dist   = float('inf')
            best_radius = 1.0
            best_label  = None

            for sig in self.known_signatures:
                ref    = np.array(sig['vector'], dtype=float)
                ref_mag = max(np.linalg.norm(ref), 1.0)
                dist   = self._mahalanobis(vec, ref)
                radius = float(sig.get('radius', ref_mag * 0.10))
                # Normalise radius to same Mahalanobis scale
                radius_m = radius / ref_mag

                if dist < best_dist:
                    best_dist   = dist
                    best_radius = radius_m
                    best_label  = sig.get('label', sig.get('name', 'Known'))

            if best_dist <= best_radius:
                return self.DEFINITE_SAFE, best_label
            elif best_dist <= best_radius * 2.0:
                return self.PROBABLE_SAFE, best_label
        except Exception:
            pass

        return self.UNKNOWN, None

    # ── Online centroid update ────────────────────────────────────────────────
    def observe(self, vector):
        if not self.known_signatures:
            return
        try:
            import math
            vec = np.array(vector, dtype=float)
            best_idx, best_norm = None, float('inf')
            for i, sig in enumerate(self.known_signatures):
                ref     = np.array(sig['vector'], dtype=float)
                ref_mag = max(np.linalg.norm(ref), 1.0)
                nd      = np.linalg.norm(vec - ref) / ref_mag
                if nd < best_norm:
                    best_norm = nd
                    best_idx  = i

            if best_idx is None:
                return
            sig     = self.known_signatures[best_idx]
            ref     = np.array(sig['vector'], dtype=float)
            ref_mag = max(np.linalg.norm(ref), 1.0)
            radius_norm = float(sig.get('radius', ref_mag * 0.10)) / ref_mag

            if best_norm > radius_norm * 2.0:
                return

            n = sig.get('hit_count', 0) + 1
            sig['hit_count'] = n

            old_c  = np.array(sig['vector'], dtype=float)
            weight = 1.0 / (1.0 + math.log10(n)) if n > 0 else 1.0
            new_c  = old_c + (vec - old_c) * weight
            sig['vector'] = new_c.tolist()

            # Drift alert
            if '_seed_centroid' not in sig:
                sig['_seed_centroid'] = old_c.tolist()
            drift = float(np.linalg.norm(new_c - np.array(sig['_seed_centroid'])))
            if drift > (ref_mag * 0.15):
                print(f"\n[KB WARNING] '{sig.get('name','?')}' drifted >15%!")

            # Welford variance of distances
            dist     = float(np.linalg.norm(vec - new_c))
            old_md   = sig.get('_mean_dist', 0.0)
            old_m2   = sig.get('_m2_dist',   0.0)
            new_md   = old_md + (dist - old_md) / n
            new_m2   = old_m2 + (dist - old_md) * (dist - new_md)
            sig['_mean_dist'] = new_md
            sig['_m2_dist']   = new_m2

            if n >= 5:
                std_d       = float(np.sqrt(new_m2 / n))
                seed_radius = float(sig.get('_seed_radius', sig.get('radius', ref_mag * 0.10)))
                sig['_seed_radius'] = seed_radius
                sig['radius'] = max(seed_radius, new_md + 2.0 * std_d)
        except Exception:
            pass

    # ── Auto-candidate: promote unknown-but-safe patterns ─────────────────────
    def auto_candidate(self, vector):
        try:
            vec = np.array(vector, dtype=float)
            mag = max(np.linalg.norm(vec), 1.0)
            bk  = tuple(np.round(vec / mag / self.CANDIDATE_BUCKET_SIZE).astype(int))

            if bk not in self._candidates:
                self._candidates[bk] = {
                    'centroid': vec.tolist(), 'hits': 0,
                    'm2': 0.0, 'mean_d': 0.0, 'first_seen': time.time()
                }

            c = self._candidates[bk]
            c['hits'] += 1
            n = c['hits']

            old_c  = np.array(c['centroid'], dtype=float)
            new_c  = old_c + (vec - old_c) / n
            c['centroid'] = new_c.tolist()

            dist   = float(np.linalg.norm(vec - new_c))
            old_md = c['mean_d']
            old_m2 = c['m2']
            new_md = old_md + (dist - old_md) / n
            new_m2 = old_m2 + (dist - old_md) * (dist - new_md)
            c['mean_d'] = new_md
            c['m2']     = new_m2

            # ── Promote? (Anti-Burst gate: KB_CANDIDATE_HITS + KB_CANDIDATE_AGE) ──
            age = time.time() - c.get('first_seen', time.time())
            if c['hits'] >= self.CANDIDATE_PROMOTE_HITS and age > KB_CANDIDATE_AGE:
                std_d  = float(np.sqrt(new_m2 / n)) if n > 1 else 0.0
                radius = max(new_md + 2.0 * std_d, mag * 0.05)
                self.known_signatures.append({
                    'name':       f'Auto-Learned ({datetime.now().strftime("%H:%M")})',
                    'vector':     new_c.tolist(),
                    'radius':     radius,
                    'hit_count':  n,
                    '_mean_dist': new_md,
                    '_m2_dist':   new_m2,
                    'auto':       True,
                })
                del self._candidates[bk]
                self.save()
                print(f"\n[KB] ✦ AUTO-LEARNED new pattern after {n} observations.")
        except Exception:
            pass


