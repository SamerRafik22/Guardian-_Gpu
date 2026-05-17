// 1. MUST BE FIRST
//#ifndef CUPTI_NO_REDEFINITIONS
//#define CUPTI_NO_REDEFINITIONS
//#endif

#include <iostream>
#include <vector>
#include <iomanip>    
#include <windows.h>  
#include <nvml.h>
#include <map>
#include <ctime>
#include <sstream>

#include "logger.h"
#include "cupti_monitor.h"
#include "stats.h"
#include "csv_logger.h"

// Helper for timestamp
std::string GetCurrentTimeStr() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S");
    return oss.str();
}

// Global accumulators for 15s buffer (Key: PID)
std::map<uint32_t, std::vector<KernelRecord>> g_csvBuffer;

int main() {
    std::cout << "[INFO] Starting Guardian GPU Monitor Phase 2..." << std::endl;

    // 1. Initialize Components
    if (!GpuMonitor::Initialize()) {
        std::cerr << "[ERROR] Failed to initialize NVML!" << std::endl;
        return 1;
    }
    
    CuptiMonitor cuptiMon;
    if (!cuptiMon.Initialize()) {
        std::cerr << "[WARNING] CUPTI init failed (Access denied?). Run as Admin." << std::endl;
    }

    CsvLogger logger;

    // 2. Get Device Handle (Assume Device 0)
    nvmlDevice_t device;
    if (nvmlDeviceGetHandleByIndex(0, &device) != NVML_SUCCESS) {
        std::cerr << "[ERROR] Failed to get GPU handle!" << std::endl;
        return 1;
    }

    char gpuName[64];
    nvmlDeviceGetName(device, gpuName, 64);
    std::cout << "[SUCCESS] Monitoring: " << gpuName << std::endl;

    // Print Header
    std::cout << "\n" 
              << std::left << std::setw(10) << "TIME"
              << std::setw(8) << "PID"
              << std::setw(15) << "NAME"
              << std::setw(10) << "MEM(MB)"
              << std::setw(8) << "PWR(W)"
              << std::setw(6) << "GPU%"
              << std::setw(5) << "FAN"
              << std::setw(10) << "CLK(C/M)"
              << std::setw(12) << "PCIe(R/T)"
              << std::setw(8) << "K/sec"
              << std::setw(10) << "LAT(us)"
              << std::setw(8) << "OCC%"
              << std::endl;
    std::cout << std::string(120, '-') << std::endl;

    // 3. Main Loop
    int tickCounter = 0;
    const int CSV_DUMP_INTERVAL_SEC = 15;

    while (true) {
        Sleep(1000); // 1 Second Loop
        tickCounter++;

        // A. Capture Data
        auto processes = GpuMonitor::CaptureProcessSnapshots(device);
        auto deviceMetrics = GpuMonitor::CaptureDeviceMetrics(device);
        auto newRecords = cuptiMon.PopRecords();

        // B. Distribute Records to Buffers
        // 1. To Console Buffer (Transient, for this loop only)
        std::map<uint32_t, std::vector<KernelRecord>> consoleBins;
        
        for (const auto& r : newRecords) {
            // For CSV accumulator
            g_csvBuffer[r.processId].push_back(r);
            // For Console display
            consoleBins[r.processId].push_back(r);
        }

        // C. Process & Print Console Rows
        std::string timeStr = GetCurrentTimeStr();

        if (processes.empty()) {
            // Idle state
        }

        for (const auto& p : processes) {
            // Get CUPTI stats for this PID (for the last 1 sec)
            AggregatedStats stats = StatsEngine::CalculateStats(consoleBins[p.pid]);

            std::cout << std::left 
                      << std::setw(10) << timeStr
                      << std::setw(8) << p.pid
                      << std::setw(15) << p.processName.substr(0, 14)
                      << std::setw(10) << (p.vramUsedBytes / 1024 / 1024)
                      << std::setw(8) << (deviceMetrics.powerUsage / 1000.0) // Shared metric
                      << std::setw(6) << p.utilizationGpu
                      << std::setw(5) << deviceMetrics.fanSpeed
                      << std::setw(4) << deviceMetrics.coreClock << "/" << std::setw(5) << deviceMetrics.memClock
                      << std::setw(5) << deviceMetrics.pcieRx << "/" << std::setw(6) << deviceMetrics.pcieTx
                      << std::setw(8) << stats.totalKernels
                      << std::setw(10) << (stats.durationMeanNs / 1000.0) // us
                      << std::setw(8) << std::fixed << std::setprecision(1) << stats.avgTheoreticalOccupancy
                      << std::endl;
        }

        // D. CSV Dump Check
        if (tickCounter >= CSV_DUMP_INTERVAL_SEC) {
            std::cout << "[INFO] Dumping CSV buffer..." << std::endl;
            
            // Collect all unique PIDs from both Sources (Buffer + Current NVML)
            std::vector<uint32_t> allPids;
            for(const auto& pair : g_csvBuffer) allPids.push_back(pair.first);
            for(const auto& p : processes) {
                bool found = false;
                for(uint32_t id : allPids) if(id == p.pid) found = true;
                if(!found) allPids.push_back(p.pid);
            }

            for (uint32_t pid : allPids) {
                // Get Kernel Records (if any)
                std::vector<KernelRecord> emptyVec;
                std::vector<KernelRecord>* recordsPtr = &emptyVec;
                if (g_csvBuffer.find(pid) != g_csvBuffer.end()) {
                    recordsPtr = &g_csvBuffer[pid];
                }
                
                // Find matching snapshot for metadata
                GpuProcessSnapshot snap; // Default empty
                bool foundSnap = false;
                for (const auto& p : processes) {
                    if (p.pid == pid) { snap = p; foundSnap = true; break; }
                }
                
                // If we have no kernels AND no active process (should be impossible due to logic above, but safety)
                if (recordsPtr->empty() && !foundSnap) continue;

                AggregatedStats stats = StatsEngine::CalculateStats(*recordsPtr);
                
                logger.LogRow(timeStr, pid, snap.processName.empty() ? "Exited/Unknown" : snap.processName,
                              snap.vramUsedBytes, deviceMetrics.powerUsage, snap.utilizationGpu,
                              deviceMetrics.temperature, deviceMetrics.fanSpeed, 
                              deviceMetrics.coreClock, deviceMetrics.memClock,
                              deviceMetrics.pcieRx, deviceMetrics.pcieTx,
                              stats.totalKernels, stats.durationMeanNs, stats.durationStdDevNs,
                              stats.avgTheoreticalOccupancy, stats.memcpyCount);
            }

            // Clear buffer
            g_csvBuffer.clear();
            tickCounter = 0;
        }
    }

    GpuMonitor::Shutdown();
    return 0;
}
