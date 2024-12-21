#pragma once
#include <vector>
#include <string>
#include <windows.h>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string path;
    std::string owner;
    std::string command_line;
};

class ProcessScanner {
public:
    std::vector<ProcessInfo> scanProcesses();
    bool killProcess(DWORD processId);
    bool isProcessRunning(DWORD processId);

private:
    std::string getProcessPath(HANDLE processHandle);
    std::string getProcessOwner(HANDLE processHandle);
    std::string getProcessCommandLine(DWORD pid);
};
