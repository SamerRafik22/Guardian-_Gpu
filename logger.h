#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>

#include "gpu_mon.h" 

class Logger {
public:
    static void Log(const std::string& msg);
    // (Other methods removed to avoid conflict, CsvLogger handles main logging)
};
