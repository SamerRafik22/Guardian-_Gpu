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
# =============================================================================
# RETRIEVAL BUFFER — cold storage reader for LOF
# =============================================================================
class RetrievalBuffer:
    MAX_NEIGHBORHOOD = 2000

    def __init__(self, archive_path=ARCHIVE_PATH, vault_path=VAULT_PATH):
        self.archive_path = archive_path
        self.vault_path   = vault_path

    def get_neighborhood(self, query_vec, n=1000):
        """Return a 2D numpy array of neighborhood vectors.
        Dimensionality matches len(query_vec) — archive (2D) columns are
        zero-padded to 6D so LOF vstack never gets a shape mismatch.
        """
        rows = []
        n_dim = len(query_vec) if query_vec is not None else 6
        n    = min(n, self.MAX_NEIGHBORHOOD)

        if os.path.exists(self.archive_path):
            try:
                data    = np.load(self.archive_path, allow_pickle=True)
                times   = data['time_ms'].astype(float)
                packets = data['packet_count'].astype(float)
                if len(times) > 0:
                    idx      = np.random.choice(len(times), min(n, len(times)), replace=False)
                    base     = np.column_stack([times[idx], packets[idx]])  # (k, 2)
                    # Pad to n_dim so LOF dataset is uniform
                    padding  = np.zeros((len(idx), max(0, n_dim - 2)))
                    rows.append(np.hstack([base, padding]))          # (k, n_dim)
            except Exception:
                pass

        needed = n - sum(len(r) for r in rows)
        if needed > 0 and os.path.exists(self.vault_path):
            try:
                vault_rows = []
                with gzip.open(self.vault_path, 'rt', encoding='utf-8') as f:
                    for line in f:
                        try:
                            rec = json.loads(line)
                            if isinstance(rec, (list, tuple)) and len(rec) >= 2:
                                # Pad or truncate to n_dim for consistency
                                vec = list(rec)[:n_dim]
                                while len(vec) < n_dim:
                                    vec.append(0.0)
                                vault_rows.append(vec)
                        except:
                            continue
                if vault_rows:
                    vr  = np.array(vault_rows, dtype=float)
                    idx = np.random.choice(len(vr), min(needed, len(vr)), replace=False)
                    rows.append(vr[idx])
            except Exception:
                pass

        return np.vstack(rows) if rows else None

    def get_archive_sample(self, n=5000):
        if not os.path.exists(self.archive_path):
            return None
        try:
            data    = np.load(self.archive_path, allow_pickle=True)
            times   = data['time_ms'].astype(float)
            packets = data['packet_count'].astype(float)
            labels  = data['activity'].astype(str) if 'activity' in data \
                      else np.array(['unknown'] * len(times))
            classes = np.unique(labels)
            per_cls = max(1, n // len(classes))
            chosen  = []
            for cls in classes:
                mask = labels == cls
                t, p = times[mask], packets[mask]
                idx  = np.random.choice(len(t), min(per_cls, len(t)), replace=False)
                chosen.append(np.column_stack([t[idx], p[idx]]))
            result = np.vstack(chosen)
            np.random.shuffle(result)
            return result[:n]
        except Exception:
            return None
# =============================================================================
# BACKGROUND ANALYZER — Ghost Thread with LOF (Tier 4)
# =============================================================================
class BackgroundAnalyzer(threading.Thread):
    LOF_NEIGHBORS    = 20
    LOF_THRESHOLD    = -1.5
    MIN_NEIGHBORHOOD = 30

    def __init__(self, knowledge_bank, retrieval_buffer):
        super().__init__()
        self.kb      = knowledge_bank
        self.rbuf    = retrieval_buffer
        self.queue   = queue.Queue()
        self.running = True
        self.daemon  = True

    def run(self):
        print("[Ghost] Thread online. LOF engine ready.")
        while self.running:
            try:
                _, data_row, iso_severity = self.queue.get(timeout=1.0)
                neighborhood  = self.rbuf.get_neighborhood(data_row, n=1000)
                final_verdict = self._run_lof(data_row, neighborhood, iso_severity)

                if final_verdict == "LOF_SAFE":
                    self.kb.auto_candidate(data_row)
                    print(f"\n[Ghost] ✓ LOF_SAFE vec={[round(x,2) for x in data_row]}")
                else:
                    print(f"\n[Ghost] ✗ LOF_THREAT iso={iso_severity:.3f}")
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Ghost] Error: {e}")

    def _run_lof(self, data_row, neighborhood, iso_severity):
        if neighborhood is None or len(neighborhood) < self.MIN_NEIGHBORHOOD:
            return "LOF_SAFE" if iso_severity > -0.55 else "LOF_THREAT"
        try:
            query = np.array(data_row, dtype=float).reshape(1, -1)
            n_dim = query.shape[1]
            # Ensure neighborhood matches query dimensionality (pad/trim)
            nb = neighborhood
            if nb.shape[1] != n_dim:
                if nb.shape[1] < n_dim:
                    pad = np.zeros((nb.shape[0], n_dim - nb.shape[1]))
                    nb  = np.hstack([nb, pad])
                else:
                    nb = nb[:, :n_dim]
            dataset = np.vstack([nb, query])
            k       = min(self.LOF_NEIGHBORS, len(dataset) - 1)
            lof     = LocalOutlierFactor(n_neighbors=k, contamination=0.05)
            lof.fit_predict(dataset)
            score = lof.negative_outlier_factor_[-1]
            return "LOF_THREAT" if score < self.LOF_THRESHOLD else "LOF_SAFE"
        except Exception:
            return "LOF_SAFE" if iso_severity > -0.55 else "LOF_THREAT"

    def submit(self, data_row, iso_severity):
        self.queue.put((1, data_row, iso_severity))
# =============================================================================
# GUARDIAN VAULT — Compressed append-only storage (unknown-safe events only)
# =============================================================================
class GuardianVault:
    def __init__(self, vault_path=VAULT_PATH):
        self.vault_path = vault_path

    def flush(self, data_chunk):
        """Append data to Vault. Enforces VAULT_MAX_ENTRIES cap with rotation."""
        if not data_chunk:
            return
        try:
            with gzip.open(self.vault_path, 'ab') as f:
                for row in data_chunk:
                    f.write((json.dumps(row) + "\n").encode('utf-8'))
            print(f"[Vault] Secured {len(data_chunk)} memories.")
            self._rotate_if_needed()
        except Exception as e:
            print(f"[Vault] Flush Failed: {e}")

    def _rotate_if_needed(self):
        """Drop oldest entries if vault exceeds VAULT_MAX_ENTRIES."""
        if not os.path.exists(self.vault_path):
            return
        try:
            lines = []
            with gzip.open(self.vault_path, 'rt', encoding='utf-8') as f:
                lines = f.readlines()
            if len(lines) <= VAULT_MAX_ENTRIES:
                return
            lines = lines[-VAULT_MAX_ENTRIES:]   # keep newest
            with gzip.open(self.vault_path, 'wt', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"[Vault] Rotated to {VAULT_MAX_ENTRIES} entries.")
        except Exception:
            pass

    def audit(self, query_vector, tolerance=None):
        """Check if a similar vector exists in vault.
        Tolerance scales with vector magnitude (10% of query norm) so it
        works correctly for any feature scale, not just tiny 2D values.
        """
        if not os.path.exists(self.vault_path):
            return False
        query = np.array(query_vector, dtype=float)
        if tolerance is None:
            tolerance = max(np.linalg.norm(query) * 0.10, 5.0)  # min 5.0
        try:
            with gzip.open(self.vault_path, 'rt', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        rec_arr = np.array(record, dtype=float)
                        # Align dimensions
                        if len(rec_arr) < len(query):
                            rec_arr = np.pad(rec_arr, (0, len(query) - len(rec_arr)))
                        elif len(rec_arr) > len(query):
                            rec_arr = rec_arr[:len(query)]
                        if np.linalg.norm(query - rec_arr) < tolerance:
                            return True
                    except:
                        continue
        except Exception:
            pass
        return False
# =============================================================================
# SLIDING WINDOW GATE — per-process sustained anomaly detector
# =============================================================================
class SlidingWindowGate:
    """Keeps a rolling window of score verdicts per process.

    Returns True (fire alert) only when >= SLIDE_WINDOW_THRESHOLD of the
    last SLIDE_WINDOW_SIZE readings are anomalous.  Single spikes = ignored.
    """

    def __init__(self):
        # {process_name: deque of bool (True=anomaly)}
        self._windows: dict[str, collections.deque] = {}

    def push(self, name: str, is_anomaly: bool) -> bool:
        """Push verdict and return True if sustained gate fires."""
        if name not in self._windows:
            self._windows[name] = collections.deque(maxlen=SLIDE_WINDOW_SIZE)
        self._windows[name].append(is_anomaly)
        count = sum(self._windows[name])
        return count >= SLIDE_WINDOW_THRESHOLD
# =============================================================================
# SUSTAINED COMPUTE GATE — Hard ceiling for continuous massive loads
# =============================================================================
class SustainedComputeGate:
    """Tracks consecutive massive GPU loads. Triggers if a process cumulatively 
    spends >= 8.0ms per 10ms tick for 70 consecutive ticks. Normal apps drop below
    this threshold instantly and decay, so only miners/hashcrackers get caught."""
    def __init__(self, threshold_ms=8.0, required_hits=70):
        self.threshold     = threshold_ms
        self.required_hits = required_hits
        self.counters: dict[str, int] = {}

    def push(self, name: str, time_ms: float) -> bool:
        if name not in self.counters:
            self.counters[name] = 0
            
        if time_ms >= self.threshold:
            self.counters[name] += 1
        else:
            # Decay counter quickly if it drops to avoid false positives on stutter
            self.counters[name] = max(0, self.counters[name] - 3)

        return self.counters[name] >= self.required_hits


# =============================================================================
# GUARDIAN BRAIN — Main Orchestrator
# =============================================================================
class GuardianBrain:
    def __init__(self):
        self.feature_cols = ['GPU_TIME_MS', 'GPU_PACKET_COUNT',
                             'PWR_W', 'MEM_MB', 'NET_TX', 'NET_RX']

        # Unified Global Model
        self.model:  IsolationForest  = None
        self.scaler: StandardScaler   = None
        self.is_trained = False

        # Unified history buffer
        self.history_buffer: list = []
        self.max_history = 5000

        # Counters
        self.learn_counter = 0
        self.save_counter  = 0

        # Components
        self.knowledge        = KnowledgeBank()
        self.vault            = GuardianVault()
        self.retrieval_buffer = RetrievalBuffer()
        self.ghost            = BackgroundAnalyzer(self.knowledge, self.retrieval_buffer)
        self.net_gate         = NetworkGate()
        self.slide_gate       = SlidingWindowGate()
        self.sustained_gate   = SustainedComputeGate()

        # Per-process grace window counters {name: event_count}
        self._grace_counters: dict[str, int] = {}

        # Whitelist manager (hot-reload from DB)
        db_path = os.path.join(_HERE, "guardian.db")
        self.whitelist = WhitelistManager(db_path)

        self.ghost.start()
        self.load_state()
        atexit.register(self.save_state)

    # ── Persistence ───────────────────────────────────────────────────────────
    def save_state(self):
        try:
            state = {
                'buffer':     self.history_buffer,
                'scaler':     self.scaler,
                'model':      self.model,
                'is_trained': self.is_trained,
                'grace':      self._grace_counters,
            }
            joblib.dump(state, MODEL_PATH, compress=3)
            self.knowledge.save()
            print(f"[Brain] State Saved: {len(self.history_buffer)} events, "
                  f"{len(self.knowledge.known_signatures)} KB sigs.")
        except Exception as e:
            print(f"[Brain] Save Failed: {e}")

    def load_state(self):
        if not os.path.exists(MODEL_PATH):
            return
        try:
            print("[Brain] Resurrecting from previous life...")
            state = joblib.load(MODEL_PATH)
            self.history_buffer   = state.get('buffer', [])
            self._grace_counters  = state.get('grace', {})

            # Load pre-trained model directly
            saved_model  = state.get('model')
            saved_scaler = state.get('scaler')

            if saved_model is not None and saved_scaler is not None:
                self.model      = saved_model
                self.scaler     = saved_scaler
                self.is_trained = state.get('is_trained', False)
                print(f"[Brain] Resurrection Complete. "
                      f"Model loaded directly. Memories: {len(self.history_buffer)}")
            else:
                self.retrain_dynamic()
                self.is_trained = True
        except Exception as e:
            print(f"[Brain] Resurrection Failed: {e}")

    # ── Training ──────────────────────────────────────────────────────────────
    def train_initial(self, log_dir_or_file):
        # Skip if we already loaded trained models from state
        if self.is_trained and self.model:
            print("[Brain] Model already loaded from saved state — skipping CSV retrain.")
            return

        df_all = None
        if os.path.isdir(log_dir_or_file):
            files = glob.glob(os.path.join(log_dir_or_file, "gpu_log_*.csv"))
            if not files:
                print("[Brain] No data found. Starting fresh.")
                self.is_trained = True
                return
            df_list = []
            for f in files[-5:]:
                try:
                    df = pd.read_csv(f)
                    for col in self.feature_cols:
                        if col not in df.columns:
                            df[col] = 0.0
                    df_list.append(df)
                except:
                    pass
            if not df_list:
                return
            df_all = pd.concat(df_list).fillna(0)
        else:
            if not os.path.exists(log_dir_or_file):
                return
            df_all = pd.read_csv(log_dir_or_file).fillna(0)
            for col in self.feature_cols:
                if col not in df_all.columns:
                    df_all[col] = 0.0

        print(f"[Brain] Training on {len(df_all)} historic events...")
        for _, row in df_all.iterrows():
            data = row.to_dict()
            vec  = [data.get(c, 0.0) for c in self.feature_cols]
            self.history_buffer.append(vec)

        self.history_buffer = self.history_buffer[-self.max_history:]

        self.retrain_dynamic()
        self.is_trained = True
        print("[Brain] Global Model Trained. Dynamic Learning Active.")

    def retrain_dynamic(self):
        if len(self.history_buffer) < 50:
            return
        try:
            X = np.array(self.history_buffer)
            if self.scaler is None:
                self.scaler = StandardScaler()
                self.model  = IsolationForest(
                    n_estimators=100,
                    contamination='auto',
                    random_state=42
                )
            self.scaler.fit(X)
            self.model.fit(self.scaler.transform(X))
            # Update Mahalanobis covariance in KB
            self.knowledge.update_covariance(X)
        except:
            pass

    # ── Main prediction cascade ───────────────────────────────────────────────
    def predict_hybrid(self, row: list, process_name: str = ""):
        """6-Tier Hybrid Cascade.

        Returns (score, severity, labels)
          score   : 1 = safe, -1 = anomaly, 0 = uncertain
          severity: IsoForest score_samples() value (0 to -1)
          labels  : list of matched label strings or special flags
        """
        known_labels = []

        # ── Tier 0a: System Whitelist (fastest, first) ────────────────────────
        if process_name and self.whitelist.is_system(process_name):
            return 1, 0.0, ["System Whitelisted"]

        # ── Tier 0b: Admin Whitelist ──────────────────────────────────────────
        if process_name and self.whitelist.is_admin(process_name):
            return 1, 0.0, ["Admin Whitelisted"]

        # ── Network Feature Gate: blend NET_TX/RX by activation phase ────────
        effective_row = self.net_gate.apply(process_name, row) if process_name else row

        # ── Periodic counters (always tick, regardless of verdict) ────────────
        self.learn_counter += 1
        if self.learn_counter >= RETRAIN_INTERVAL:
            self.retrain_dynamic()
            self.learn_counter = 0

        self.save_counter += 1
        if self.save_counter >= SAVE_INTERVAL:
            self.save_state()
            self.save_counter = 0

        # ── Tier 1c: Sustained Compute Trap ──────────────────────────────────
        time_ms = float(effective_row[0])
        is_sustained = self.sustained_gate.push(process_name, time_ms)
        if process_name and is_sustained:
            return -1, -1.0, ["SUSTAINED_COMPUTE_TRAP"]

        # ── Tier 1b: Per-process Grace Window ────────────────────────────────
        grace_count = self._grace_counters.get(process_name, 0) + 1
        self._grace_counters[process_name] = grace_count
        if process_name and grace_count <= GRACE_WINDOW:
            # During grace: collect into buffer (we're learning, not detecting)
            self._safe_buffer_append(effective_row)
            return 0, 0.0, ["GRACE_WINDOW"]

        # ── Tier 2: Knowledge Bank ────────────────────────────────────────────
        confidence, label = self.knowledge.is_known(
            effective_row, name_override=process_name
        )
        if label:
            known_labels = [label]

        if confidence == KnowledgeBank.DEFINITE_SAFE:
            self.knowledge.observe(effective_row)
            self._safe_buffer_append(effective_row)  # ← safe confirmed
            return 1, 0.5, known_labels

        # ── Tier 3: IsolationForest — score_samples(), fixed threshold ────────
        if not self.is_trained or self.model is None:
            # No model yet — collect into buffer optimistically
            self._safe_buffer_append(effective_row)
            return 0, 0.0, known_labels

        model  = self.model
        scaler = self.scaler

        try:
            X        = np.array([effective_row])
            X_scaled = scaler.transform(X)
            severity = float(model.score_samples(X_scaled)[0])  # ← score_samples, NOT predict
            is_anomaly = severity < ANOMALY_SCORE_THRESHOLD

            if not is_anomaly:
                # ── SAFE: only now add to training buffer ─────────────────────
                self._safe_buffer_append(effective_row)
                if confidence == KnowledgeBank.PROBABLE_SAFE:
                    self.knowledge.observe(effective_row)
                else:
                    self.knowledge.auto_candidate(effective_row)
            # If anomalous: do NOT add to buffer — don't train on threats

            # ── Tier 3b: Ambiguity → Ghost/LOF ───────────────────────────────
            if -0.7 < severity < -0.4:
                if confidence == KnowledgeBank.PROBABLE_SAFE:
                    self.knowledge.observe(effective_row)
                    self._safe_buffer_append(effective_row)
                    return 1, severity, known_labels
                is_historic = self.vault.audit(effective_row, tolerance=2.0)
                if is_historic:
                    self.knowledge.auto_candidate(effective_row)
                    self._safe_buffer_append(effective_row)
                    return 1, 0.5, known_labels
                else:
                    self.ghost.submit(effective_row, severity)

            # ── Tier 4: Sliding Window Gate ───────────────────────────────────
            should_alert = self.slide_gate.push(process_name, is_anomaly)

            if is_anomaly and not should_alert:
                return 0, severity, known_labels

            if is_anomaly:
                known_labels = known_labels or ["ANOMALY"]

            score = -1 if (is_anomaly and should_alert) else 1
            return score, severity, known_labels

        except Exception:
            return 0, 0, known_labels

    def _safe_buffer_append(self, vec: list):
        """Add a CONFIRMED-SAFE event vector to the history buffer.
        Overflow flushes oldest 500 entries to Vault for LOF neighbourhood.
        This is the ONLY place history_buffers should be written to.
        Anomalous events are never added here.
        """
        self.history_buffer.append(vec)
        if len(self.history_buffer) > self.max_history:
            overflow = self.history_buffer[:500]
            self.vault.flush(overflow)
            self.history_buffer = self.history_buffer[500:]
# =============================================================================
# CSV ARCHIVER — Session Data Pipeline (FIXED: uses 6 features)
# =============================================================================
VRAM_OVERFLOW = 17592186044415

class CSVArchiver:
    """Watches log directories. Archives completed CSVs to .npz.

    Routes rows by type:
      SUSPICIOUS_COPY → vault only (threat evidence)
      Non-whitelisted, known safe → kb.observe()
      Non-whitelisted, unknown safe → kb.auto_candidate()
      All non-garbage → guardian_archive.npz

    Whitelisted processes are SKIPPED entirely — no pollution of KB/Vault.
    """
    ARCHIVE_PATH = ARCHIVE_PATH

    _COL_ALIASES = {
        'GPU_TIME_MS':      ['GPU_TIME_MS', 'Duration_Mean_ns'],
        'GPU_PACKET_COUNT': ['GPU_PACKET_COUNT', 'Kernels_Count'],
        'PROCESS_NAME':     ['ProcessName', 'NAME', 'Name'],
    }

    def __init__(self, log_dirs, brain: 'GuardianBrain'):
        self.log_dirs = [log_dirs] if isinstance(log_dirs, str) else list(log_dirs)
        self.brain    = brain
        self._done    = set()

    def bootstrap(self):
        print("[Archiver] Bootstrap scan starting...")
        total = 0
        for d in self.log_dirs:
            total += self._archive_dir(d, leave_newest=False)
        print(f"[Archiver] Bootstrap complete. {total} sessions archived.")

    def scan_and_archive(self):
        for d in self.log_dirs:
            self._archive_dir(d, leave_newest=True)

    def _archive_dir(self, log_dir, leave_newest):
        if not os.path.isdir(log_dir):
            return 0
        files = sorted(glob.glob(os.path.join(log_dir, "gpu_log_*.csv")),
                       key=os.path.getmtime)
        if leave_newest and files:
            files = files[:-1]
        count = 0
        for f in files:
            if f not in self._done:
                self._process_session(f)
                count += 1
        return count

    def _resolve_col(self, df, key):
        for alias in self._COL_ALIASES.get(key, [key]):
            if alias in df.columns:
                return alias
        return None

    def _process_session(self, csv_path):
        fname = os.path.basename(csv_path)
        try:
            df = pd.read_csv(csv_path, on_bad_lines='skip')
        except Exception as e:
            print(f"[Archiver] Cannot read '{fname}': {e}")
            self._done.add(csv_path)
            return

        if df.empty:
            os.remove(csv_path)
            self._done.add(csv_path)
            return

        col_time  = self._resolve_col(df, 'GPU_TIME_MS')
        col_count = self._resolve_col(df, 'GPU_PACKET_COUNT')
        col_name  = self._resolve_col(df, 'PROCESS_NAME')

        if col_time is None or col_count is None:
            self._done.add(csv_path)
            return

        # Ensure all 6 feature columns exist
        feature_map = {
            'GPU_TIME_MS':      col_time,
            'GPU_PACKET_COUNT': col_count,
            'PWR_W':            'PWR_W'   if 'PWR_W'   in df.columns else None,
            'MEM_MB':           'MEM_MB'  if 'MEM_MB'  in df.columns else None,
            'NET_TX':           'NET_TX'  if 'NET_TX'  in df.columns else None,
            'NET_RX':           'NET_RX'  if 'NET_RX'  in df.columns else None,
        }
        # Fill missing feature cols with 0
        for feat, col in feature_map.items():
            if col is None:
                df[feat] = 0.0

        for col in [col_time, col_count]:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

        if 'VRAM_Used_MB' in df.columns:
            df = df[df['VRAM_Used_MB'].astype(str) != str(VRAM_OVERFLOW)]
        df = df[(df[col_time] != 0) | (df[col_count] != 0)].copy()

        if df.empty:
            os.remove(csv_path)
            self._done.add(csv_path)
            return

        df['_activity'] = df.apply(
            lambda r: classify_activity({
                'GPU_TIME_MS': r[col_time], 'GPU_PACKET_COUNT': r[col_count]
            }), axis=1
        )

        kb_obs, candidates, vault_rows = 0, 0, []
        archive_t, archive_p, archive_a, archive_n = [], [], [], []

        for _, row in df.iterrows():
            # Build full 6-feature vector
            vec = [
                float(row.get(feature_map.get('GPU_TIME_MS') or col_time, 0)),
                float(row.get(feature_map.get('GPU_PACKET_COUNT') or col_count, 0)),
                float(row.get('PWR_W',  0)),
                float(row.get('MEM_MB', 0)),
                float(row.get('NET_TX', 0)),
                float(row.get('NET_RX', 0)),
            ]
            activity = row['_activity']
            name     = str(row[col_name]) if col_name and col_name in df.columns \
                       else 'Unknown'

            # Skip whitelisted processes — don't pollute KB/Vault
            if self.brain.whitelist.is_system(name) or self.brain.whitelist.is_admin(name):
                continue

            if activity == 'SUSPICIOUS_COPY':
                vault_rows.append(vec)
            else:
                conf, _ = self.brain.knowledge.is_known(vec)
                if conf in (KnowledgeBank.DEFINITE_SAFE, KnowledgeBank.PROBABLE_SAFE):
                    self.brain.knowledge.observe(vec)
                    kb_obs += 1
                else:
                    self.brain.knowledge.auto_candidate(vec)
                    candidates += 1

            archive_t.append(vec[0])
            archive_p.append(vec[1])
            archive_a.append(activity)
            archive_n.append(name)

        if vault_rows:
            self.brain.vault.flush(vault_rows)

        if archive_t:
            self._append_to_archive(
                np.array(archive_t), np.array(archive_p),
                np.array(archive_a), np.array(archive_n)
            )

        try:
            os.remove(csv_path)
        except Exception as e:
            print(f"[Archiver] Could not delete '{fname}': {e}")

        self._done.add(csv_path)
        print(f"[Archiver] '{fname}' → {kb_obs} KB | {candidates} candidates | "
              f"{len(vault_rows)} vault | {len(archive_t)} archived")

    def _append_to_archive(self, times, packets, activities, names):
        if os.path.exists(self.ARCHIVE_PATH):
            try:
                old    = np.load(self.ARCHIVE_PATH, allow_pickle=True)
                times      = np.concatenate([old['time_ms'],      times])
                packets    = np.concatenate([old['packet_count'], packets])
                activities = np.concatenate([old['activity'],     activities])
                names      = np.concatenate([old['process_name'], names])
            except Exception:
                pass
        np.savez_compressed(self.ARCHIVE_PATH,
                            time_ms=times, packet_count=packets,
                            activity=activities, process_name=names)


# =============================================================================
# HELPERS
# =============================================================================
def classify_activity(data):
    time_ms = float(data.get('GPU_TIME_MS', 0))
    count   = float(data.get('GPU_PACKET_COUNT', 0))

    if count > 200 and time_ms < 1.0:
        return "SUSPICIOUS_COPY"

    # Pure GPU Compute: very long execution time + FEW dispatch calls
    # (Hashcat, miners, ML training — not games which have hundreds of draw calls)
    if time_ms > 500.0 and count < 50:
        return "Compute"

    # Heavy compute fallback (e.g. video encode, physics sim, miners — high time)
    if time_ms > 100.0:
        return "Compute"

    # Gaming: many draw calls per frame (high count) + moderate execution time
    if count > 100 and time_ms > 15.0:
        return "Gaming"

    if count > 50:
        return "3D/UI Activity"

    return "Idle"


def parse_line(line):
    try:
        parts = line.strip().split(',')
        if len(parts) < 7:
            return None
        if "TIMESTAMP" in parts[0]:
            return None

        has_net = (len(parts) >= 9)
        obj = {}
        obj['PID']  = parts[1]
        obj['NAME'] = parts[2].replace('"', '')

        if has_net:
            obj['NET_RX']           = float(parts[-1])
            obj['NET_TX']           = float(parts[-2])
            obj['GPU_PACKET_COUNT'] = float(parts[-3])
            obj['GPU_TIME_MS']      = float(parts[-4])
            obj['PWR_W']            = float(parts[-5])
            mem = float(parts[-6])
            obj['MEM_MB'] = mem if mem < 100000 else 0.0
        else:
            obj['NET_RX']           = 0.0
            obj['NET_TX']           = 0.0
            obj['GPU_PACKET_COUNT'] = float(parts[-1]) if len(parts) >= 7 else 0.0
            obj['GPU_TIME_MS']      = float(parts[-2]) if len(parts) >= 6 else 0.0
            obj['PWR_W']            = float(parts[-3]) if len(parts) >= 5 else 3.0
            mem = float(parts[-4]) if len(parts) >= 4 else 512.0
            obj['MEM_MB'] = mem if mem < 100000 else 0.0

        return obj
    except Exception:
        return None


# =============================================================================
# STANDALONE MAIN (used when running guardian_brain.py directly, not via live.py)
# =============================================================================
def main():
    print("----------------------------------------------------------------")
    print("   GUARDIAN BRAIN - Live Anomaly Detection System")
    print("----------------------------------------------------------------")

    brain    = GuardianBrain()
    archiver = CSVArchiver([LOG_DIR, BUILD_RELEASE_DIR], brain)
    archiver.bootstrap()
    brain.train_initial(LOG_DIR)

    streamer          = _LogStreamer(LOG_DIR)
    last_archive_scan = time.time()
    ARCHIVE_INTERVAL  = 60

    print("[Streamer] Watching for live events...")
    try:
        while True:
            lines = streamer.stream_lines()
            for line in lines:
                data = parse_line(line)
                if data:
                    category = classify_activity(data)
                    vec      = [data[c] for c in brain.feature_cols]
                    name     = data.get('NAME', 'Unknown')
                    score, severity, aux = brain.predict_hybrid(
                        vec, activity_class=category, process_name=name
                    )

                    if aux == "SUSPICIOUS_COPY_TRAP" or category == "SUSPICIOUS_COPY":
                        score = -1

                    if score == -1:
                        print(f"\n!!! ANOMALY !!! [{severity:.4f}] "
                              f"PID:{data['PID']} ({name}) {category}")

            if time.time() - last_archive_scan >= ARCHIVE_INTERVAL:
                archiver.scan_and_archive()
                last_archive_scan = time.time()

            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")


class _LogStreamer:
    """Minimal log streamer for standalone brain main()."""
    def __init__(self, log_dir):
        self.log_dir     = log_dir
        self.current     = None
        self.file_handle = None

    def _latest(self):
        files = glob.glob(os.path.join(self.log_dir, "gpu_log_*.csv"))
        return max(files, key=os.path.getmtime) if files else None

    def stream_lines(self):
        latest = self._latest()
        if not latest:
            return []
        if latest != self.current:
            if self.file_handle:
                self.file_handle.close()
            self.current     = latest
            self.file_handle = open(self.current, 'r')
            self.file_handle.seek(0, 2)
        return self.file_handle.readlines()


if __name__ == "__main__":
    main()
