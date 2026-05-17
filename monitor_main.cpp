#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <set>
#include <tlhelp32.h>
#include <fstream>
#include <sstream>
#include <map>
#include <mutex>
#include <algorithm>
#include <ctime>

#include <sddl.h> // For ConvertStringSecurityDescriptorToSecurityDescriptor
#include "gpu_mon.h"
#include "etw_monitor.h" 
#include "logger.h"
#include "csv_logger.h"

// -----------------------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------------------
std::string GetTimestamp() {
    auto t  = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::mutex g_statsMutex;

std::set<std::string> g_blacklist = {
    "csrss.exe", "dwm.exe", "smss.exe", "services.exe", 
    "lsass.exe", "wininit.exe", "svchost.exe", "RuntimeBroker.exe",
    "Registry", "System", "Idle", "Memory Compression",
    "GuardianMonitor.exe", "SleepyApp.exe" 
};

// -----------------------------------------------------------------------------
// MAIN MONITOR LOOP
// -----------------------------------------------------------------------------
int main() {
    std::cout << "[GuardianMonitor] Starting Phase 5: ETW Passive Monitoring..." << std::endl;

    // 1. Initialize NVML
    if (!GpuMonitor::Initialize()) {
        std::cerr << "[Error] NVML Init Failed!" << std::endl;
        return 1;
    }
    nvmlDevice_t device;
    nvmlDeviceGetHandleByIndex(0, &device); // Assume GPU 0
    unsigned int g_numProcsLastCycle = 0; // Track CUDA process count for utilization split

    // 2. Start ETW Session
    EtwMonitor g_etwMonitor;
    if (!g_etwMonitor.StartSession()) {
        std::cerr << "[Error] Failed to start ETW Session. Run as Admin?" << std::endl;
        // Proceed anyway? No, ETW is core now.
        return 1;
    }

    CsvLogger logger;

    std::cout << "\n" 
              << std::left << std::setw(10) << "TIME"
              << std::setw(8) << "PID"
              << std::setw(20) << "NAME"
              << std::setw(10) << "MEM(MB)"
              << std::setw(8) << "PWR(W)"
              << std::setw(12) << "GPU_TIME(ms)"
              << std::setw(8) << "COUNTS"
              << std::setw(8) << "NET_TX"  // New
              << std::setw(8) << "NET_RX"  // New
              << std::endl;
    std::cout << "------------------------------------------------------------------------------------------------" << std::endl;

    while (true) {
        Sleep(10); // 10ms → 100Hz drain rate, ETW accumulates continuously at kernel speed

        // A. Scan Processes via NVML (catches CUDA compute: miners, hashcat, etc.)
        auto nvmlProcs = GpuMonitor::CaptureProcessSnapshots(device);
        auto deviceMetrics = GpuMonitor::CaptureDeviceMetrics(device);

        // A2. Sample global GPU utilization for CUDA compute fallback
        nvmlUtilization_t globalUtil = {0, 0};
        nvmlDeviceGetUtilizationRates(device, &globalUtil);
        // If multiple CUDA processes share the GPU, split utilization evenly
        unsigned int activeCudaProcs = (unsigned int)nvmlProcs.size();
        if (activeCudaProcs == 0) activeCudaProcs = 1;
        // Scale: 100% util over 10ms tick = 10ms synthetic GPU time per process
        double utilPerProcMs = (globalUtil.gpu / 100.0) * 10.0 / activeCudaProcs;
        
        // B. Get ETW Stats (Passive)
        // Returns usage since last call
        auto etwStats = g_etwMonitor.PopProcessUsage(); 

        // C. Display & Log
        std::string timeStr = GetTimestamp();
        
        bool printedHeader = false;

        for (const auto& p : nvmlProcs) {
            double gpuTimeMs = 0.0;
            uint32_t packetCount = 0;
            uint64_t netTx = 0;
            uint64_t netRx = 0;

            if (etwStats.count(p.pid)) {
                gpuTimeMs = etwStats[p.pid].busyTimeMs;
                packetCount = etwStats[p.pid].packetCount;
                netTx = etwStats[p.pid].netTxBytes;
                netRx = etwStats[p.pid].netRxBytes;
            }

            // CUDA Compute Fallback: ETW misses CUDA/OpenCL workloads (miners, hashcat)
            // If global GPU util is high but ETW sees no GPU time, synthesize from global util.
            // This catches disguised miners even when DxgKrnl events are silent.
            if (gpuTimeMs < 0.1 && globalUtil.gpu > 10) {
                gpuTimeMs = utilPerProcMs;
                packetCount = (uint32_t)(globalUtil.gpu); // Use util% as proxy packet count
            }
            
            // Only print if active
            if (gpuTimeMs > 0.1 || p.vramUsedBytes > 50*1024*1024) { // 50MB threshold catches early CUDA alloc
                 std::cout << std::left << std::setw(10) << " "
                      << std::setw(8) << p.pid
                      << std::setw(20) << p.processName.substr(0, 19)
                      << std::setw(10) << (p.vramUsedBytes / 1024 / 1024)
                      << std::setw(8) << (deviceMetrics.powerUsage / 1000.0)
                      << std::setw(12) << std::fixed << std::setprecision(2) << gpuTimeMs
                      << std::setw(8) << packetCount
                      << std::setw(8) << netTx
                      << std::setw(8) << netRx
                      << std::endl;
            }

            // Log CSV (Simplified)
            logger.LogRow(
                timeStr,
                p.pid, p.processName,
                p.vramUsedBytes, (deviceMetrics.powerUsage / 1000.0), gpuTimeMs, packetCount,
                netTx, netRx
            );
        }
    }

    return 0;
}
