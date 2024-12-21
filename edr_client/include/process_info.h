#pragma once
#include <string>
#include <vector>

struct ProcessInfo {
    unsigned long pid;
    std::string name;
    std::string path;
    std::string owner;
    std::string commandLine;
    unsigned long parentPid;
    std::vector<std::string> modules;
    std::string status;
    double cpuUsage;
    size_t memoryUsage;
};
