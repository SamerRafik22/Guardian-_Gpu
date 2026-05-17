#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>

class CsvLogger {
public:
    CsvLogger() {
        // Create filename with timestamp: gpu_log_YYYYMMDD_HHMMSS.csv
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << "gpu_log_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".csv";
        m_filename = oss.str();

        // Open file ONCE and keep it open — avoids repeated lock/unlock per row
        m_file.open(m_filename, std::ios::out);
        if (m_file.is_open()) {
            m_file << "TIMESTAMP,PID,NAME,MEM_MB,PWR_W,GPU_TIME_MS,GPU_PACKET_COUNT,NET_TX,NET_RX\n";
            m_file.flush();
            std::cout << "[INFO] CSV Logger initiated: " << m_filename << std::endl;
        } else {
            std::cerr << "[ERROR] Failed to create CSV file: " << m_filename << std::endl;
        }
    }

    ~CsvLogger() {
        // Flush and close cleanly on shutdown so no data is lost
        if (m_file.is_open()) {
            m_file.flush();
            m_file.close();
        }
    }

    void LogRow(const std::string& timestamp,
                uint32_t pid, const std::string& procName,
                uint64_t vram, double power, double gpuTimeMs, uint32_t packetCount,
                uint64_t netTx, uint64_t netRx)
    {
        if (!m_file.is_open()) return;

        // FIX: NVML returns -1 (18446744073709551615) when memory is not available.
        // Divide by 1024*1024 to convert bytes → MB, set to 0 if unavailable.
        uint64_t vram_mb = (vram == (uint64_t)-1 || vram > 100000000000ULL) ? 0 : vram / (1024ULL * 1024ULL);

        // Security Fix: Sanitize process name to prevent CSV Injection (Delimiter Spoofing)
        std::string safeProcName = procName;
        for (char& c : safeProcName) {
            if (c == '"' || c == ',' || c == '\n' || c == '\r') {
                c = '_'; // Strip out quotes and commas
            }
        }

        m_file << timestamp << ","
               << pid << "," << "\"" << safeProcName << "\","
               << vram_mb << ","
               << std::fixed << std::setprecision(1) << power << ","
               << std::setprecision(2) << gpuTimeMs << ","
               << packetCount << ","
               << netTx << ","
               << netRx << "\n";

        // Flush after every row — guarantees Python can read complete lines immediately
        m_file.flush();
    }

private:
    std::string   m_filename;
    std::ofstream m_file;   // Persistent handle — opened once, closed on destruction
};
