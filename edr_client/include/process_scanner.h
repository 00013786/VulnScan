#ifndef PROCESS_SCANNER_H
#define PROCESS_SCANNER_H

#include <string>
#include <vector>
#include "process_info.h"

class ProcessScanner {
public:
    ProcessScanner();
    ~ProcessScanner();

    std::vector<ProcessInfo> scanProcesses();
};

#endif // PROCESS_SCANNER_H
