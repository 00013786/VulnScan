#include "behavior_monitor.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <ctime>

std::vector<SuspiciousActivity> BehaviorMonitor::checkForSuspiciousActivities() {
    std::vector<SuspiciousActivity> activities;
    
    // Get snapshot of current processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return activities;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return activities;
    }

    // Get current timestamp
    time_t now = time(0);
    char timestamp[26];
    ctime_s(timestamp, sizeof(timestamp), &now);

    do {
        std::string processName;
        char procName[MAX_PATH];
        wcstombs(procName, pe32.szExeFile, MAX_PATH);
        processName = procName;

        // Check for process injection
        if (checkProcessInjection(pe32.th32ProcessID, processName)) {
            SuspiciousActivity activity;
            activity.type = "Process Injection";
            activity.description = "Potential process injection detected";
            activity.pid = pe32.th32ProcessID;
            activity.processName = processName;
            activity.timestamp = timestamp;
            activities.push_back(activity);
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);

    // Check for unusual network connections
    if (checkUnusualConnections()) {
        SuspiciousActivity activity;
        activity.type = "Unusual Network Activity";
        activity.description = "Suspicious network connections detected";
        activity.timestamp = timestamp;
        activities.push_back(activity);
    }

    return activities;
}

bool BehaviorMonitor::checkProcessInjection(DWORD pid, std::string& processName) {
    // This is a simplified check. In a real EDR, you would implement more sophisticated detection
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (processHandle == NULL) {
        return false;
    }

    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T result = VirtualQueryEx(processHandle, 0, &memInfo, sizeof(memInfo));
    CloseHandle(processHandle);

    // Look for suspicious memory permissions
    return (result != 0 && 
            (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE);
}

bool BehaviorMonitor::checkUnusualConnections() {
    // Implement checks for suspicious network connections
    // This would typically involve checking for connections to known malicious IPs
    // or unusual ports
    return false;
}

bool BehaviorMonitor::checkSuspiciousFileOperations() {
    // Implement checks for suspicious file operations
    // This would typically involve monitoring for file modifications in system directories
    // or suspicious file extensions
    return false;
}
