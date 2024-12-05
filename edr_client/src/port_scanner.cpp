#include "port_scanner.h"
#include <iphlpapi.h>
#include <iostream>

#pragma comment(lib, "iphlpapi.lib")

PortScanner::PortScanner() {
    initializeWinsock();
}

PortScanner::~PortScanner() {
    cleanup();
}

bool PortScanner::initializeWinsock() {
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

void PortScanner::cleanup() {
    WSACleanup();
}

std::vector<PortInfo> PortScanner::scanPorts() {
    std::vector<PortInfo> ports;
    
    // Get TCP table
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    // Make an initial call to GetTcpTable to get the necessary size into the dwSize variable
    if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
        ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)new char[dwSize];
        if (pTcpTable == NULL) {
            return ports;
        }
    }

    // Make a second call to GetTcpTable to get the actual data we require
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) ==
        NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            PortInfo info;
            info.port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            info.protocol = "TCP";
            info.pid = pTcpTable->table[i].dwOwningPid;
            
            // Get process name from PID
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
            if (processHandle) {
                char processName[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameA(processHandle, 0, processName, &size)) {
                    info.processName = processName;
                }
                CloseHandle(processHandle);
            }

            switch (pTcpTable->table[i].dwState) {
                case MIB_TCP_STATE_LISTEN:
                    info.state = "LISTENING";
                    break;
                case MIB_TCP_STATE_ESTAB:
                    info.state = "ESTABLISHED";
                    break;
                default:
                    info.state = "OTHER";
            }

            ports.push_back(info);
        }
    }

    delete[] pTcpTable;
    return ports;
}
