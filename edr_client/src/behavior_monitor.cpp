#include "behavior_monitor.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <ctime>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <vector>
#include <iomanip>

std::vector<SuspiciousActivity> BehaviorMonitor::checkForSuspiciousActivities() {
    std::vector<SuspiciousActivity> activities;
    
    // Get snapshot of current processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return activities;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    // Get first process
    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return activities;
    }
    
    // Iterate through processes
    do {
        // Convert process name to string for comparison
        std::wstring wProcessName(pe32.szExeFile);
        std::string processName(wProcessName.begin(), wProcessName.end());
        
        // Check for suspicious process names
        if (isSuspiciousProcessName(processName)) {
            SuspiciousActivity activity;
            activity.type = "SUSPICIOUS_PROCESS";
            activity.description = "Suspicious process name detected";
            activity.processName = processName;
            
            // Get current timestamp
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
            activity.timestamp = ss.str();
            
            activities.push_back(activity);
        }
        
        // Check process memory and behavior
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            if (hasHighMemoryUsage(hProcess)) {
                SuspiciousActivity activity;
                activity.type = "HIGH_MEMORY_USAGE";
                activity.description = "Process is using unusually high memory";
                activity.processName = processName;
                
                auto now = std::chrono::system_clock::now();
                auto time = std::chrono::system_clock::to_time_t(now);
                std::stringstream ss;
                ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
                activity.timestamp = ss.str();
                
                activities.push_back(activity);
            }
            
            if (hasSuspiciousThreads(hProcess)) {
                SuspiciousActivity activity;
                activity.type = "SUSPICIOUS_THREADS";
                activity.description = "Process has suspicious thread activity";
                activity.processName = processName;
                
                auto now = std::chrono::system_clock::now();
                auto time = std::chrono::system_clock::to_time_t(now);
                std::stringstream ss;
                ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
                activity.timestamp = ss.str();
                
                activities.push_back(activity);
            }
            
            CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return activities;
}

bool BehaviorMonitor::isSuspiciousProcessName(const std::string& processName) {
    // Convert to lowercase for case-insensitive comparison
    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    // List of suspicious process names
    static const std::vector<std::string> suspiciousNames = {
        "mimikatz",
        "pwdump",
        "procdump",
        "lazagne",
        "gsecdump",
        "wce",
        "lsass.exe",
        "ntds.dit"
    };
    
    return std::any_of(suspiciousNames.begin(), suspiciousNames.end(),
        [&lowerName](const std::string& suspicious) {
            return lowerName.find(suspicious) != std::string::npos;
        });
}

bool BehaviorMonitor::hasHighMemoryUsage(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        // Flag if working set size is greater than 1GB
        return pmc.WorkingSetSize > (1024 * 1024 * 1024);
    }
    return false;
}

bool BehaviorMonitor::hasSuspiciousThreads(HANDLE hProcess) {
    DWORD processId = GetProcessId(hProcess);
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    int threadCount = 0;
    
    if (!Thread32First(hThreadSnapshot, &te32)) {
        CloseHandle(hThreadSnapshot);
        return false;
    }
    
    do {
        if (te32.th32OwnerProcessID == processId) {
            threadCount++;
        }
    } while (Thread32Next(hThreadSnapshot, &te32));
    
    CloseHandle(hThreadSnapshot);
    
    // Flag if process has more than 100 threads
    return threadCount > 100;
}

bool BehaviorMonitor::checkUnusualConnections() {
    // This would check for unusual network connections
    // For now, return false as this is not implemented yet
    return false;
}
