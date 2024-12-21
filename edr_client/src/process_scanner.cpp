#include "process_scanner.h"
#include <tlhelp32.h>
#include <iostream>
#include <winternl.h>
#include <psapi.h>

std::vector<ProcessInfo> ProcessScanner::scanProcesses() {
    std::vector<ProcessInfo> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        std::cerr << "Failed to get first process. Error: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return processes;
    }

    do {
        ProcessInfo info;
        info.pid = pe32.th32ProcessID;
        
        // Convert wide string to UTF-8
        std::wstring wName(pe32.szExeFile);
        info.name = std::string(wName.begin(), wName.end());
        
        // Get process handle for additional information
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
        if (hProcess != NULL) {
            info.path = getProcessPath(hProcess);
            info.owner = getProcessOwner(hProcess);
            info.command_line = getProcessCommandLine(info.pid);
            CloseHandle(hProcess);
        } else {
            info.path = "";
            info.owner = "";
            info.command_line = "";
        }

        processes.push_back(info);
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
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

std::string ProcessScanner::getProcessOwner(HANDLE hProcess) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return "";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return "";
    }

    std::vector<BYTE> buffer(dwSize);
    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        CloseHandle(hToken);
        return "";
    }

    WCHAR name[256];
    DWORD nameSize = sizeof(name)/sizeof(WCHAR);
    WCHAR domain[256];
    DWORD domainSize = sizeof(domain)/sizeof(WCHAR);
    SID_NAME_USE sidType;

    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType)) {
        CloseHandle(hToken);
        return "";
    }

    CloseHandle(hToken);
    std::wstring wOwner = std::wstring(domain) + L"\\" + std::wstring(name);
    return std::string(wOwner.begin(), wOwner.end());
}

std::string ProcessScanner::getProcessCommandLine(DWORD pid) {
    // Getting command line requires higher privileges, so we'll skip it for now
    return "";
}

bool ProcessScanner::isProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    DWORD exitCode;
    bool isRunning = true;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        isRunning = (exitCode == STILL_ACTIVE);
    }

    CloseHandle(hProcess);
    return isRunning;
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

    // Wait a bit and verify the process is actually terminated
    Sleep(500); // Wait 500ms for the process to terminate
    bool isStillRunning = isProcessRunning(processId);
    
    if (isStillRunning) {
        std::cerr << "Process " << processId << " is still running after termination attempt" << std::endl;
        return false;
    }

    std::cout << "Successfully terminated process " << processId << std::endl;
    return true;
}
