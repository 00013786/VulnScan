#include "process_scanner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <memory>
#include <iostream>

ProcessScanner::ProcessScanner() {}

ProcessScanner::~ProcessScanner() {}

std::string wstringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    try {
        std::string str(wstr.begin(), wstr.end());
        return str;
    } catch (const std::exception& e) {
        std::cerr << "Error converting wstring to string: " << e.what() << std::endl;
        return "";
    }
}

std::vector<ProcessInfo> ProcessScanner::scanProcesses() {
    std::vector<ProcessInfo> processes;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot" << std::endl;
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::cerr << "Failed to get first process" << std::endl;
        return processes;
    }

    do {
        try {
            // Skip processes with PID 0 (System Idle Process)
            if (pe32.th32ProcessID == 0) {
                continue;
            }

            ProcessInfo process;
            process.pid = pe32.th32ProcessID;
            process.parentPid = pe32.th32ParentProcessID;
            process.name = wstringToString(std::wstring(pe32.szExeFile));

            // Skip if we couldn't get the process name
            if (process.name.empty()) {
                continue;
            }

            // Get process handle
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.pid);
            if (hProcess) {
                // Get process path
                wchar_t path[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
                    process.path = wstringToString(std::wstring(path));
                }

                // Get process owner
                HANDLE hToken = NULL;
                if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                    DWORD dwSize = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        std::vector<BYTE> buffer(dwSize);
                        if (GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
                            PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
                            wchar_t name[256];
                            wchar_t domain[256];
                            DWORD nameSize = 256;
                            DWORD domainSize = 256;
                            SID_NAME_USE sidType;
                            if (LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &nameSize,
                                                domain, &domainSize, &sidType)) {
                                std::wstring owner = std::wstring(domain) + L"\\" + std::wstring(name);
                                process.owner = wstringToString(owner);
                            }
                        }
                    }
                    CloseHandle(hToken);
                }

                // Get command line (simplified version)
                process.commandLine = process.path;  // Just use the path as command line for now

                // Get process status
                process.status = "Running";

                // Get CPU and memory usage
                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                    ULARGE_INTEGER kernelTimeValue, userTimeValue;
                    kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
                    kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
                    userTimeValue.LowPart = userTime.dwLowDateTime;
                    userTimeValue.HighPart = userTime.dwHighDateTime;

                    process.cpuUsage = (kernelTimeValue.QuadPart + userTimeValue.QuadPart) / 10000000.0;
                }

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    process.memoryUsage = pmc.WorkingSetSize / 1024.0;  // Convert to KB
                }

                // Get loaded modules
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        wchar_t szModName[MAX_PATH];
                        if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                            std::string modulePath = wstringToString(std::wstring(szModName));
                            if (!modulePath.empty()) {
                                process.modules.push_back(modulePath);
                            }
                        }
                    }
                }

                CloseHandle(hProcess);
            } else {
                // If we can't open the process, at least set some basic info
                process.path = "Access Denied";
                process.owner = "Unknown";
                process.commandLine = process.name;
                process.status = "Running";
                process.cpuUsage = 0.0;
                process.memoryUsage = 0;
            }

            processes.push_back(process);
        } catch (const std::exception& e) {
            std::cerr << "Error processing process: " << e.what() << std::endl;
            continue;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return processes;
}
