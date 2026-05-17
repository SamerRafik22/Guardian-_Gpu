#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <mutex>

// Link with tdh.lib and advapi32.lib

class EtwMonitor {
public:
    EtwMonitor();
    ~EtwMonitor();

    bool StartSession();
    void StopSession();

    // Stats Access
    struct ProcessStats {
        double busyTimeMs;     // Cumulative GPU time (Duration)
        uint32_t packetCount;  // Number of work chunks (Frequency)
        uint64_t netTxBytes;   // New: Network Transmit
        uint64_t netRxBytes;   // New: Network Receive
    };
    
    // Get collected usage since last call (and reset counters)
    std::map<uint32_t, ProcessStats> PopProcessUsage();

private:
    void WorkerThread();
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);

    // Internal Helpers
    static void ParseDxgKrnlEvent(PEVENT_RECORD pEvent);

private:
    TRACEHANDLE m_hSession = 0;
    TRACEHANDLE m_hTrace = 0;
    std::string m_sessionName = "GuardianGpuSession_Active";
    
    std::thread m_workerThread;
    std::atomic<bool> m_isRunning{false};

    // Shared State (Static because callback is C-style static)
    static std::mutex s_statsMutex;
    static std::map<uint32_t, ProcessStats> s_gpuUsageMap; // PID -> Stats
    static std::map<uint64_t, uint64_t> s_contextActiveStart; // ContextHandle -> StartTimestamp
    static std::map<uint64_t, uint32_t> s_contextPidMap;      // ContextHandle -> PID
};
