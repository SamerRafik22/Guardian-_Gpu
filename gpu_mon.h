#pragma once
#include <nvml.h>
#include <vector>
#include <string>

struct GpuProcessSnapshot {
    uint32_t pid;
    std::string processName;
    unsigned long long vramUsedBytes;
    unsigned int utilizationGpu; // %
    
    // Stats added by Guardian
    uint32_t kernelCount = 0;
    double durationMeanNs = 0;
    double durationStdDevNs = 0;
    double occupancy = 0;
};

struct GpuDeviceMetrics {
    unsigned int powerUsage; // mW
    unsigned int temperature; // C
    unsigned int fanSpeed; // %
    unsigned int coreClock; // MHz
    unsigned int memClock; // MHz
    unsigned int pcieRx; // KB/s
    unsigned int pcieTx; // KB/s
};

class GpuMonitor {
public:
    static bool Initialize();
    static void Shutdown();
    static std::vector<GpuProcessSnapshot> CaptureProcessSnapshots(nvmlDevice_t device);
    static GpuDeviceMetrics CaptureDeviceMetrics(nvmlDevice_t device);
};
