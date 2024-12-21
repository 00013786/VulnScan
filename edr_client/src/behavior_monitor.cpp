#include "behavior_monitor.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <vector>
#include <functional>

BehaviorMonitor::BehaviorMonitor() {
}

BehaviorMonitor::~BehaviorMonitor() {
}

std::vector<SuspiciousActivity> BehaviorMonitor::detectSuspiciousActivities() {
    std::vector<SuspiciousActivity> activities;

    detectProcessInjection(activities);
    detectUnauthorizedAccess(activities);
    detectSuspiciousNetworkActivity(activities);

    // Notify handlers of new activities
    for (const auto& activity : activities) {
        for (const auto& handler : activityHandlers) {
            handler(activity);
        }
    }

    return activities;
}

void BehaviorMonitor::addActivityHandler(std::function<void(const SuspiciousActivity&)> handler) {
    activityHandlers.push_back(handler);
}

bool BehaviorMonitor::detectProcessInjection(std::vector<SuspiciousActivity>& activities) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            std::wstring wProcessName(pe32.szExeFile);
            std::string processName(wProcessName.begin(), wProcessName.end());

            if (isSuspiciousProcessName(processName) || 
                hasHighMemoryUsage(hProcess) || 
                hasSuspiciousThreads(hProcess)) {
                
                SuspiciousActivity activity;
                activity.type = "process_injection";
                activity.description = "Suspicious behavior detected in process: " + processName;
                activity.source = processName;
                activity.sourcePid = pe32.th32ProcessID;
                activity.severity = "high";
                activity.timestamp = std::chrono::system_clock::now();
                
                activities.push_back(activity);
            }

            CloseHandle(hProcess);
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return true;
}

bool BehaviorMonitor::detectUnauthorizedAccess(std::vector<SuspiciousActivity>& activities) {
    // This is a placeholder. In practice, you'd monitor file system and registry access
    return true;
}

bool BehaviorMonitor::detectSuspiciousNetworkActivity(std::vector<SuspiciousActivity>& activities) {
    // This is a placeholder. In practice, you'd monitor network connections
    return true;
}

bool BehaviorMonitor::isSuspiciousProcessName(const std::string& processName) {
    // List of potentially suspicious process names
    const std::vector<std::string> suspiciousNames = {
        "mimikatz",
        "pwdump",
        "procdump",
        "lazagne",
        "ghostpack",
        "psexec",
        "bloodhound",
        "cobalt",
        "metasploit"
    };

    for (const auto& name : suspiciousNames) {
        if (processName.find(name) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool BehaviorMonitor::hasHighMemoryUsage(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        // Flag if process is using more than 1GB of memory
        const SIZE_T threshold = 1024 * 1024 * 1024;  // 1GB in bytes
        return pmc.WorkingSetSize > threshold;
    }
    return false;
}

bool BehaviorMonitor::hasSuspiciousThreads(HANDLE hProcess) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    DWORD processId = GetProcessId(hProcess);
    int threadCount = 0;

    if (!Thread32First(snapshot, &te32)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (te32.th32OwnerProcessID == processId) {
            threadCount++;
        }
    } while (Thread32Next(snapshot, &te32));

    CloseHandle(snapshot);

    // Flag if process has an unusually high number of threads
    return threadCount > 100;  // This threshold should be adjusted based on your needs
}
