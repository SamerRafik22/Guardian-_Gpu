import psutil
import os
import windows_killer

def execute_kill(pid: str, name: str) -> dict:
    """
    Direct execution for Kill command from Web UI (Page-Fault Architecture).
    Safely executes a kill on the exact requested PID tree, and then
    aggressively sweeps the system for any remaining processes sharing the name.
    """
    killed = []
    
    target_pid = None
    try:
        if pid and pid != "0":
            target_pid = int(pid)
    except ValueError:
        pass
        
    # Phase 1: Surgical Tree Kill
    # If a specific PID was provided, kill it and all its children.
    if target_pid:
        local_killed = windows_killer.force_kill_tree(target_pid=target_pid)
        killed.extend(local_killed)
        
    # Phase 2: "Surfing Memory" Catch-All
    # If the app self-spawns (e.g., msedge.exe) or we only have a name,
    # perform a sweeping name-based kill of all remaining instances.
    if name and name != "Unknown":
        base_name = os.path.basename(name.replace('\\', '/'))
        local_killed = windows_killer.force_kill_tree(process_name=base_name)
        killed.extend(local_killed)
        
    # Deduplicate PID list
    killed = list(set(killed))
    
    if killed:
        return {"status": "success", "message": f"{name} terminated ({len(killed)} processes)."}
    else:
        return {"status": "error", "message": f"Could not find or kill {name}."}

def execute_suspend(pid: str, name: str) -> dict:
    """
    Direct execution for Suspend command from Web UI.
    Freezes the target process in memory instead of killing it.
    """
    try:
        if not pid or pid == "0":
            return {"status": "error", "message": "Valid PID required for suspend."}
            
        p = psutil.Process(int(pid))
        p.suspend()
        return {"status": "success", "message": f"{name} suspended in memory."}
    except psutil.NoSuchProcess:
        return {"status": "error", "message": f"Process {pid} no longer exists."}
    except Exception as e:
        return {"status": "error", "message": f"Suspend failed: {str(e)}"}
