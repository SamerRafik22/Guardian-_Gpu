import collections
import time
import numpy as np

class PIDTracker:
    def __init__(self, max_history=60):
        # Maps PID -> dict of state
        self.pids = {}
        self.max_history = max_history

    def update(self, pid, name, row_vec, activity_class, score, severity, is_kb_match):
        """
        row_vec: [time_ms, packets, pwr_w, mem_mb, net_tx, net_rx]
        """
        now = time.time()
        pid = str(pid)

        if pid not in self.pids:
            self.pids[pid] = {
                "name": name,
                "first_seen": now,
                "window": collections.deque(maxlen=self.max_history),
                "alert_count": 0,
                "class": activity_class,
                "is_gaming_whitelist": (activity_class == "Gaming" and is_kb_match)
            }

        state = self.pids[pid]
        
        # If it ever gets whitelisted as Gaming, lock it down
        if activity_class == "Gaming" and is_kb_match:
            state["is_gaming_whitelist"] = True

        if score == -1:
            state["alert_count"] += 1
            
        state["window"].append({
            "ts": now,
            "vec": row_vec,
            "score": score,
            "severity": severity
        })

    def get_all(self):
        return self.pids
        
    def cleanup_stale(self, timeout=300):
        """Remove PIDs that haven't been seen recently."""
        now = time.time()
        stale = [p for p, data in self.pids.items() 
                 if len(data["window"]) > 0 and (now - data["window"][-1]["ts"] > timeout)]
        for p in stale:
            del self.pids[p]


class SustainedAttackDetector:
    def __init__(self):
        pass
        
    def run(self, tracker):
        """
        Evaluates active PIDs in the tracker.
        Returns a list of alerts: [{'pid': id, 'name': n, 'type': 'ALERT_TYPE', 'msg': str}, ...]
        """
        alerts = []
        now = time.time()
        
        for pid, data in tracker.get_all().items():
            # Skip hard whitelisted Gaming
            if data["is_gaming_whitelist"]:
                continue
                
            window = data["window"]
            if len(window) < 10:
                continue # Needs more history
                
            # Extract time series
            gpu_times = np.array([w["vec"][0] for w in window])
            packet_counts = np.array([w["vec"][1] for w in window])
            pwr_watts = np.array([w["vec"][2] for w in window])
            
            # --- Test 1: Machine-like Variance (Mining/Cracking) ---
            # Miners run a perfect loop, frames/kernels take exact same ns every time.
            # Humans/games have high variance.
            if len(gpu_times) > 20:
                mean_time = np.mean(gpu_times)
                std_time = np.std(gpu_times)
                
                # Rule: High compute load but near-zero variance
                if mean_time > 10.0 and std_time < 0.5:
                    alerts.append({
                        "pid": pid,
                        "name": data["name"],
                        "type": "SUSTAINED_CRACKING_MINING",
                        "severity": -0.99,
                        "msg": f"Machine-like execution variance ({std_time:.2f}ms)"
                    })
                    
            # --- Test 2: Drift / Exfiltration (CUSUM proxy) ---
            # Rising monotonic network or memory copy trend
            if len(packet_counts) > 20:
                deltas = np.diff(packet_counts)
                positive_moves = np.sum(deltas > 0)
                negative_moves = np.sum(deltas < 0)
                
                # If packets strictly keep climbing monotonically
                if positive_moves > 15 and negative_moves < 2:
                     # This usually means iterative memory dumping
                     alerts.append({
                        "pid": pid,
                        "name": data["name"],
                        "type": "SUSTAINED_MEMORY_EXFIL",
                        "severity": -0.98,
                        "msg": "Unnatural monotonic packet accumulation"
                    })
                     
            # --- Test 3: Session Age Anomalies ---
            session_age = now - data["first_seen"]
            alert_ratio = data["alert_count"] / len(window)
            
            # If it's been throwing mild alerts consistently for > 15 minutes
            if session_age > 900 and alert_ratio > 0.05:
                 alerts.append({
                     "pid": pid,
                     "name": data["name"],
                     "type": "LONG_TERM_MALICIOUS_SESSION",
                     "severity": -0.9,
                     "msg": f"Chronically anomalous session ({int(session_age/60)}m)"
                 })

        # --- Test 4: Coordinated Attack across PIDs ---
        # Look for multiple unknown PIDs spawning clustered together
        if len(tracker.pids) > 5:
            recent_unknowns = 0
            for pid, data in tracker.pids.items():
                if not data["is_gaming_whitelist"] and data["alert_count"] > 0:
                    age = now - data["first_seen"]
                    if age < 60: # Spawned in last minute
                        recent_unknowns += 1
            if recent_unknowns >= 3:
                alerts.append({
                     "pid": "MULTIPLE",
                     "name": f"{recent_unknowns} PIDs",
                     "type": "COORDINATED_SYSTEM_ATTACK",
                     "severity": -1.0,
                     "msg": "Multiple unknown PIDs spawning anomalous activity"
                })
                    
        return alerts
