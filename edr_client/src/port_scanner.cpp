#include "port_scanner.h"
#include <iphlpapi.h>
#include <iostream>
#include <vector>

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
    
    // Get the size needed for the TCP table
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return ports;
    }
    
    // Allocate memory for the TCP table
    std::vector<BYTE> buffer(size);
    PMIB_TCPTABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    
    // Get the actual TCP table
    result = GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        return ports;
    }
    
    // Iterate through the TCP table
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        PortInfo info;
        info.port = ntohs(static_cast<u_short>(pTcpTable->table[i].dwLocalPort));
        info.protocol = "TCP";
        
        // Get process information
        DWORD pid = pTcpTable->table[i].dwOwningPid;
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle != NULL) {
            char processName[MAX_PATH];
            DWORD size = sizeof(processName);
            if (QueryFullProcessImageNameA(processHandle, 0, processName, &size)) {
                info.processName = processName;
                info.process = std::to_string(pid) + " (" + processName + ")";
            }
            CloseHandle(processHandle);
        }
        
        // Get connection state
        switch (pTcpTable->table[i].dwState) {
            case MIB_TCP_STATE_CLOSED:
                info.state = "CLOSED";
                break;
            case MIB_TCP_STATE_LISTEN:
                info.state = "LISTENING";
                break;
            case MIB_TCP_STATE_ESTAB:
                info.state = "ESTABLISHED";
                break;
            default:
                info.state = "OTHER";
                break;
        }
        
        ports.push_back(info);
    }
    
    return ports;
}
