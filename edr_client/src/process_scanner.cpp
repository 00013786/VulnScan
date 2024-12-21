#include "process_scanner.h"
#include <tlhelp32.h>
#include <iostream>
#include <winternl.h>
#include <psapi.h>

std::vector<ProcessInfo> ProcessScanner::scanProcesses() {
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot: " << GetLastError() << std::endl;
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        std::cerr << "Failed to get first process: " << GetLastError() << std::endl;
        CloseHandle(snapshot);
        return processes;
    }

    do {
        // Skip System Idle Process (PID 0)
        if (pe32.th32ProcessID == 0) {
            continue;
        }

        ProcessInfo info;
        info.pid = pe32.th32ProcessID;
        
        // Convert wide string to regular string
        char processName[MAX_PATH];
        wcstombs(processName, pe32.szExeFile, MAX_PATH);
        info.name = processName;

        // Get process handle with minimum required permissions
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
        if (processHandle != NULL) {
            info.path = getProcessPath(processHandle);
            info.commandLine = getProcessCommandLine(info.pid);
            CloseHandle(processHandle);
        } else {
            // If we can't open the process, at least set the name from the snapshot
            info.path = info.name; // Use executable name as path
            info.commandLine = ""; // Empty command line
            if (GetLastError() != ERROR_ACCESS_DENIED) {
                std::cerr << "Failed to open process " << info.pid << ": " << GetLastError() << std::endl;
            }
        }

        // Only add processes that have at least a name
        if (!info.name.empty()) {
            processes.push_back(info);
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return processes;
}

std::string ProcessScanner::getProcessPath(HANDLE process) {
    char buffer[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameA(process, 0, buffer, &size)) {
        return std::string(buffer);
    }

    // Fallback to GetModuleFileNameEx if QueryFullProcessImageNameA fails
    if (GetModuleFileNameExA(process, NULL, buffer, MAX_PATH)) {
        return std::string(buffer);
    }

    return ""; // Return empty string if we can't get the path
}

std::string ProcessScanner::getProcessCommandLine(DWORD pid) {
    // Getting command line requires higher privileges, so we'll skip it for now
    return "";
}

bool ProcessScanner::killProcess(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process " << processId << " for termination. Error: " << GetLastError() << std::endl;
        return false;
    }

    bool success = TerminateProcess(hProcess, 1);
    DWORD error = GetLastError();
    CloseHandle(hProcess);

    if (!success) {
        std::cerr << "Failed to terminate process " << processId << ". Error: " << error << std::endl;
        return false;
    }

    std::cout << "Successfully terminated process " << processId << std::endl;
    return true;
}
