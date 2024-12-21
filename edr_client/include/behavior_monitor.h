#pragma once
#include <vector>
#include <string>
#include <windows.h>

struct SuspiciousActivity {
    std::string type;
    std::string description;
    std::string processName;
    std::string timestamp;
};

class BehaviorMonitor {
public:
    std::vector<SuspiciousActivity> checkForSuspiciousActivities();
    bool checkUnusualConnections();

private:
    bool isSuspiciousProcessName(const std::string& processName);
    bool hasHighMemoryUsage(HANDLE hProcess);
    bool hasSuspiciousThreads(HANDLE hProcess);
};
