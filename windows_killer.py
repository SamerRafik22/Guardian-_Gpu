import os
import ctypes
import psutil

# Constants for OpenProcess
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400

# Kernel32 functions
kernel32 = ctypes.windll.kernel32
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
OpenProcess.restype = ctypes.c_void_p

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
TerminateProcess.restype = ctypes.c_int

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]
CloseHandle.restype = ctypes.c_int


def _sys_kill_pid(pid: int) -> bool:
    """Uses Windows API TerminateProcess to forcefully kill a PID."""
    if pid <= 0:
        return False
        
    try:
        # Open the process with termination rights
        handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return False
            
        # Terminate immediately with exit code 1
        result = TerminateProcess(handle, 1)
        CloseHandle(handle)
        return bool(result)
    except Exception as e:
        print(f"Error in syscall kill for PID {pid}: {e}")
        return False

def force_kill_tree(target_pid: int = None, process_name: str = None) -> list:
    """
    Finds the target process by PID or name, collects all its child processes, 
    and forcefully terminates them all via Windows syscalls.
    Returns a list of PIDs that were terminated.
    """
    killed_pids = []
    targets = []
    
    try:
        if target_pid:
            # Try to grab the specific process by ID
            try:
                targets = [psutil.Process(target_pid)]
            except psutil.NoSuchProcess:
                pass
                
        if not targets and process_name:
            # Fallback: grab all processes matching the name
            proc_name_lower = process_name.lower()
            for p in psutil.process_iter(['pid', 'name']):
                if p.info['name'] and p.info['name'].lower() == proc_name_lower:
                    targets.append(p)
                    
        if not targets:
            return killed_pids
            
        procs_to_kill = set()
        
        # Collect targets and all their children
        for t in targets:
            procs_to_kill.add(t)
            try:
                children = t.children(recursive=True)
                for c in children:
                    procs_to_kill.add(c)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        # Send syscall terminate to all collected processes
        # Kill children first to prevent them spawning more things as parent dies
        sorted_procs = sorted(list(procs_to_kill), key=lambda x: x.create_time(), reverse=True)
        
        for p in sorted_procs:
            pid = p.pid
            success = _sys_kill_pid(pid)
            if success:
                killed_pids.append(pid)
            else:
                # Fallback to psutil kill if syscall fails
                try:
                    p.kill()
                    killed_pids.append(pid)
                except:
                    pass
                    
        return killed_pids
        
    except Exception as e:
        print(f"Failed to kill tree: {e}")
        return killed_pids
