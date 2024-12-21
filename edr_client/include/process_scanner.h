#pragma once
#include <vector>
#include <string>
#include <windows.h>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string path;
    std::string commandLine;
};

class ProcessScanner {
public:
    std::vector<ProcessInfo> scanProcesses();
    bool killProcess(DWORD processId);

private:
    std::string getProcessPath(HANDLE processHandle);
    std::string getProcessCommandLine(DWORD pid);
};
