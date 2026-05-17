#include "gpu_mon.h"
#include <iostream>

bool GpuMonitor::Initialize() {
    nvmlReturn_t result = nvmlInit();
    if (NVML_SUCCESS != result) {
        std::cerr << "Failed to initialize NVML: " << nvmlErrorString(result) << std::endl;
        return false;
    }
    return true;
}

void GpuMonitor::Shutdown() {
    nvmlShutdown();
}

std::vector<GpuProcessSnapshot> GpuMonitor::CaptureProcessSnapshots(nvmlDevice_t device) {
    std::vector<GpuProcessSnapshot> snapshots;
    
    // Get running processes
    unsigned int infoCount = 100;
    nvmlProcessInfo_t infos[100];
    nvmlReturn_t ret = nvmlDeviceGetComputeRunningProcesses(device, &infoCount, infos);
    
    if (ret == NVML_SUCCESS) {
        for (unsigned int i = 0; i < infoCount; i++) {
            GpuProcessSnapshot snap;
            snap.pid = infos[i].pid;
            snap.vramUsedBytes = infos[i].usedGpuMemory;
            
            // Get Name
            char name[256];
            if (nvmlSystemGetProcessName(snap.pid, name, 256) == NVML_SUCCESS) {
                snap.processName = name;
            } else {
                snap.processName = "Unknown";
            }
            
            // In a real app, you'd calculate utilization per process (hard with just NVML)
            // We use global utilization for now or assume activity
            snap.utilizationGpu = 0; 
            
            snapshots.push_back(snap);
        }
    }
    
    return snapshots;
}

GpuDeviceMetrics GpuMonitor::CaptureDeviceMetrics(nvmlDevice_t device) {
    GpuDeviceMetrics m;
    nvmlDeviceGetPowerUsage(device, &m.powerUsage);
    nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, &m.temperature);
    nvmlDeviceGetFanSpeed(device, &m.fanSpeed);
    nvmlDeviceGetClockInfo(device, NVML_CLOCK_GRAPHICS, &m.coreClock);
    nvmlDeviceGetClockInfo(device, NVML_CLOCK_MEM, &m.memClock);
    // Use correct enums or simplified (0 for now if API differs between SDKs)
    unsigned int rx=0, tx=0;
    // nvmlDeviceGetPcieThroughput(device, NVML_PCIE_UTIL_RX, &rx); // Revisit later
    m.pcieRx = rx;
    m.pcieTx = tx;
    return m;
}
