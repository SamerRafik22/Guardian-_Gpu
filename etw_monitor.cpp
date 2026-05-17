#include "etw_monitor.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include "stealth_importer.h"

// ---------------------------------------------------------
// STEALTH IMPORTER: Dynamic ETW Resolution
// ---------------------------------------------------------
inline ULONG StealthControlTraceA(TRACEHANDLE h, LPCSTR n, PEVENT_TRACE_PROPERTIES p, ULONG c) {
    auto f = StealthResolve<ULONG(WINAPI*)(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES, ULONG)>("advapi32.dll", "ControlTraceA");
    return f ? f(h, n, p, c) : ERROR_PROC_NOT_FOUND;
}
inline ULONG StealthStartTraceA(PTRACEHANDLE h, LPCSTR n, PEVENT_TRACE_PROPERTIES p) {
    auto f = StealthResolve<ULONG(WINAPI*)(PTRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES)>("advapi32.dll", "StartTraceA");
    return f ? f(h, n, p) : ERROR_PROC_NOT_FOUND;
}
inline ULONG StealthEnableTraceEx2(TRACEHANDLE h, LPCGUID g, ULONG c, UCHAR l, ULONGLONG k1, ULONGLONG k2, ULONG t, PENABLE_TRACE_PARAMETERS p) {
    auto f = StealthResolve<ULONG(WINAPI*)(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PENABLE_TRACE_PARAMETERS)>("advapi32.dll", "EnableTraceEx2");
    return f ? f(h, g, c, l, k1, k2, t, p) : ERROR_PROC_NOT_FOUND;
}
inline TRACEHANDLE StealthOpenTraceA(PEVENT_TRACE_LOGFILEA l) {
    auto f = StealthResolve<TRACEHANDLE(WINAPI*)(PEVENT_TRACE_LOGFILEA)>("advapi32.dll", "OpenTraceA");
    return f ? f(l) : (TRACEHANDLE)INVALID_HANDLE_VALUE;
}
inline ULONG StealthProcessTrace(PTRACEHANDLE h, ULONG c, LPFILETIME s, LPFILETIME e) {
    auto f = StealthResolve<ULONG(WINAPI*)(PTRACEHANDLE, ULONG, LPFILETIME, LPFILETIME)>("advapi32.dll", "ProcessTrace");
    return f ? f(h, c, s, e) : ERROR_PROC_NOT_FOUND;
}
inline ULONG StealthCloseTrace(TRACEHANDLE h) {
    auto f = StealthResolve<ULONG(WINAPI*)(TRACEHANDLE)>("advapi32.dll", "CloseTrace");
    return f ? f(h) : ERROR_PROC_NOT_FOUND;
}

#define ControlTraceA StealthControlTraceA
#define StartTraceA StealthStartTraceA
#define EnableTraceEx2 StealthEnableTraceEx2
#define OpenTraceA StealthOpenTraceA
#define ProcessTrace StealthProcessTrace
#define CloseTrace StealthCloseTrace
// ---------------------------------------------------------

// Link Helpers
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Static Members
std::mutex EtwMonitor::s_statsMutex;
std::map<uint32_t, EtwMonitor::ProcessStats> EtwMonitor::s_gpuUsageMap;
std::map<uint64_t, uint64_t> EtwMonitor::s_contextActiveStart;
std::map<uint64_t, uint32_t> EtwMonitor::s_contextPidMap;

// GUID for Microsoft-Windows-DxgKrnl
// {802ec45a-1e99-4b83-9920-87c98277ba9d}
static const GUID DXGKRNL_GUID = 
{ 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };

// GUID for Microsoft-Windows-TCPIP
// {2F07E2EE-15DB-40F1-90EF-9D7BA2821888}
static const GUID TCPIP_GUID = 
{ 0x2F07E2EE, 0x15DB, 0x40F1, { 0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x88 } };

EtwMonitor::EtwMonitor() {}

EtwMonitor::~EtwMonitor() {
    StopSession();
}

bool EtwMonitor::StartSession() {
    if (m_isRunning) return true;

    // 1. Setup Session Properties
    // We need a large buffer for properties + name
    const size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<char> buffer(buffSize);
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)buffer.data();
    
    ZeroMemory(pProps, buffSize);
    pProps->Wnode.BufferSize = (ULONG)buffSize;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1; // QPC
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); // Name follows struct
    // pProps->LogFileNameOffset = 0; // No file, real-time

    // 2. Force-stop any existing zombie session, then flush before reuse
    ControlTraceA(0, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);
    Sleep(500); // Flush window: give kernel time to fully release the session handle

    // Retry loop with exponential backoff — handles race condition on fast relaunch
    ULONG status = ERROR_ALREADY_EXISTS;
    for (int attempt = 1; attempt <= 3; attempt++) {
        // Re-initialize pProps each attempt (StartTraceA modifies the buffer)
        ZeroMemory(pProps, buffSize);
        pProps->Wnode.BufferSize    = (ULONG)buffSize;
        pProps->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        pProps->Wnode.ClientContext  = 1; // QPC
        pProps->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        pProps->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

        status = StartTraceA(&m_hSession, m_sessionName.c_str(), pProps);
        if (status == ERROR_SUCCESS) break;

        std::cerr << "[ETW] StartTrace attempt " << attempt
                  << " failed (" << status << "). Retrying..." << std::endl;
        ControlTraceA(0, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);
        Sleep(1000 * attempt); // backoff: 1s → 2s → 3s
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] Failed to start ETW session after 3 attempts: " << status << std::endl;
        return false;
    }

    // 3. Enable Provider (DxgKrnl)
    // Keywords: 
    // 0x1 = Base
    // 0x20 = Processes/Contexts ?
    // Let's enable ALL keywords for now to discover (0xFFFFFF...)
    status = EnableTraceEx2(
        m_hSession,
        &DXGKRNL_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0xFFFFFFFFFFFFFFFF, // Match Any Keyword
        0, // Match All Keyword
        0,
        NULL
    );

    // 3b. Enable Provider (TCPIP)
    // TEMPORARILY DISABLED: Debugging Zero Stats Issue
    /*
    status = EnableTraceEx2(
        m_hSession,
        &TCPIP_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 
        0, 
        0,
        NULL
    );
     if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] Failed to EnableTrace (TCPIP): " << status << std::endl;
        // Don't fail the whole session for this
    }
    */

    // 4. Start Consumer Thread
    m_isRunning = true;
    m_workerThread = std::thread(&EtwMonitor::WorkerThread, this);
    
    std::cout << "[ETW] Session Started! Listening for GPU Kernel Events..." << std::endl;
    return true;
}

void EtwMonitor::StopSession() {
    if (!m_isRunning) return;
    
    m_isRunning = false;
    
    // Close Trace processing to unblock thread
    if (m_hTrace) {
        CloseTrace(m_hTrace);
        m_hTrace = 0;
    }

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }

    // Stop Session
    EVENT_TRACE_PROPERTIES props = { 0 };
    props.Wnode.BufferSize = sizeof(props);
    ControlTraceA(m_hSession, m_sessionName.c_str(), &props, EVENT_TRACE_CONTROL_STOP);
    
    m_hSession = 0;
}

void EtwMonitor::WorkerThread() {
    EVENT_TRACE_LOGFILEA logFile = { 0 };
    logFile.LoggerName = (char*)m_sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwMonitor::EventRecordCallback;
    logFile.Context = this;

    m_hTrace = OpenTraceA(&logFile);
    if (m_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW] OpenTrace failed." << std::endl;
        return;
    }

    // Blocks until CloseTrace is called
    ProcessTrace(&m_hTrace, 1, NULL, NULL);
}

// -----------------------------------------------------------------------------
// EVENT HANDLER
// -----------------------------------------------------------------------------

// Known Headers
struct DxgKrnl_ContextAlloc_Event {
    // This is pseudo-code structure, actual fields need TDH parsing
    // Usually contains hContext, PID, DeviceHandle
};

void WINAPI EtwMonitor::EventRecordCallback(PEVENT_RECORD pEvent) {
    // 1. GPU Kernel Events
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, DXGKRNL_GUID)) {
        uint32_t pid = pEvent->EventHeader.ProcessId;
        if (pid == 0) return;

        UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
        
        if (opcode == 1) { // START
            uint32_t tid = pEvent->EventHeader.ThreadId;
            std::lock_guard<std::mutex> lock(s_statsMutex);
            s_contextActiveStart[tid] = pEvent->EventHeader.TimeStamp.QuadPart;
            s_gpuUsageMap[pid].packetCount++; // GPU Packet
        }
        else if (opcode == 2) { // STOP
            uint32_t tid = pEvent->EventHeader.ThreadId;
            std::lock_guard<std::mutex> lock(s_statsMutex);
            if (s_contextActiveStart.count(tid)) {
                uint64_t start = s_contextActiveStart[tid];
                uint64_t end = pEvent->EventHeader.TimeStamp.QuadPart;
                if (end > start) {
                    uint64_t deltaRaw = end - start;
                    double durationMs = deltaRaw / 10000.0; 
                    s_gpuUsageMap[pid].busyTimeMs += durationMs;
                }
                s_contextActiveStart.erase(tid);
            }
        }
    }
    // 2. Network TCPIP Events
    else if (IsEqualGUID(pEvent->EventHeader.ProviderId, TCPIP_GUID)) {
        uint32_t pid = pEvent->EventHeader.ProcessId;
        if (pid == 0) return;

        // Opcode 10 = Task Send
        // Opcode 11 = Task Receive
        // This is a rough heuristic for "Activity"
        UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
        
        std::lock_guard<std::mutex> lock(s_statsMutex);
        if (opcode >= 10 && opcode <= 20) { // Send range
             s_gpuUsageMap[pid].netTxBytes++; // Just counting events (packets)
        } else if (opcode >= 40 && opcode <= 50) { // Recv range guess or simple toggle
             // Actually TCPIP opcodes vary by version. 
             // Let's simplified: If Opcode is "Send" like, add Tx.
             // For now, ANY event is "Activity", we just want the PID.
             // We'll dump all into Tx for simplicity or split blindly.
             s_gpuUsageMap[pid].netTxBytes++;
        }
        else {
             s_gpuUsageMap[pid].netRxBytes++;
        }
    }
}

std::map<uint32_t, EtwMonitor::ProcessStats> EtwMonitor::PopProcessUsage() {
    std::lock_guard<std::mutex> lock(s_statsMutex);
    auto ret = s_gpuUsageMap;
    s_gpuUsageMap.clear(); // Reset for next interval (Rate/Sec)
    return ret;
}
