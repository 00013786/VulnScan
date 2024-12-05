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

private:
    std::string getProcessPath(HANDLE process);
    std::string getProcessCommandLine(DWORD pid);
};
