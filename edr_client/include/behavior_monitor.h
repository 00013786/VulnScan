#pragma once

#include <vector>
#include <string>
#include <functional>
#include <windows.h>
#include "suspicious_activity.h"

class BehaviorMonitor {
public:
    BehaviorMonitor();
    ~BehaviorMonitor();

    std::vector<SuspiciousActivity> detectSuspiciousActivities();
    void addActivityHandler(std::function<void(const SuspiciousActivity&)> handler);

private:
    std::vector<std::function<void(const SuspiciousActivity&)>> activityHandlers;
    bool detectProcessInjection(std::vector<SuspiciousActivity>& activities);
    bool detectUnauthorizedAccess(std::vector<SuspiciousActivity>& activities);
    bool detectSuspiciousNetworkActivity(std::vector<SuspiciousActivity>& activities);
    bool isSuspiciousProcessName(const std::string& processName);
    bool hasHighMemoryUsage(HANDLE hProcess);
    bool hasSuspiciousThreads(HANDLE hProcess);
};
