#pragma once
#include <vector>
#include <string>
#include <windows.h>

struct SuspiciousActivity {
    std::string type;
    std::string description;
    DWORD pid;
    std::string processName;
    std::string timestamp;
};

class BehaviorMonitor {
public:
    std::vector<SuspiciousActivity> checkForSuspiciousActivities();
private:
    bool checkProcessInjection(DWORD pid, std::string& processName);
    bool checkUnusualConnections();
    bool checkSuspiciousFileOperations();
};
