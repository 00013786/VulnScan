#include "port_scanner.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <iostream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

PortScanner::PortScanner() {
    initializeWinsock();
}

PortScanner::~PortScanner() {
    cleanup();
}

bool PortScanner::initializeWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

void PortScanner::cleanup() {
    WSACleanup();
}

std::vector<PortInfo> PortScanner::scanPorts() {
    std::vector<PortInfo> ports;
    
    // Get TCP table
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    // Make an initial call to GetTcpTable to get the necessary size into dwSize
    dwRetVal = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
    if (pTcpTable == NULL) {
        return ports;
    }

    dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRetVal == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            PortInfo info;
            info.port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            info.protocol = "TCP";
            
            // Get local address
            struct in_addr addr;
            addr.s_addr = pTcpTable->table[i].dwLocalAddr;
            char localAddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, localAddr, sizeof(localAddr));
            info.localAddress = localAddr;

            // Get remote address
            addr.s_addr = pTcpTable->table[i].dwRemoteAddr;
            char remoteAddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, remoteAddr, sizeof(remoteAddr));
            info.remoteAddress = remoteAddr;

            // Get state
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
            }

            // Get process info
            info.pid = pTcpTable->table[i].dwOwningPid;
            info.processName = getProcessNameByPid(info.pid);

            ports.push_back(info);
        }
    }

    free(pTcpTable);

    // Get UDP table
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    dwSize = 0;

    dwRetVal = GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    
    pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
    if (pUdpTable == NULL) {
        return ports;
    }

    dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRetVal == NO_ERROR) {
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
            PortInfo info;
            info.port = ntohs((u_short)pUdpTable->table[i].dwLocalPort);
            info.protocol = "UDP";
            
            // Get local address
            struct in_addr addr;
            addr.s_addr = pUdpTable->table[i].dwLocalAddr;
            char localAddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, localAddr, sizeof(localAddr));
            info.localAddress = localAddr;
            
            info.remoteAddress = "*"; // UDP is connectionless
            info.state = "LISTENING";
            
            // Get process info
            info.pid = pUdpTable->table[i].dwOwningPid;
            info.processName = getProcessNameByPid(info.pid);

            ports.push_back(info);
        }
    }

    free(pUdpTable);
    return ports;
}

bool PortScanner::isPortOpen(unsigned short port, const std::string& protocol) {
    if (protocol == "TCP") {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int result = connect(sock, (SOCKADDR*)&addr, sizeof(addr));
        closesocket(sock);
        
        return result != SOCKET_ERROR;
    }
    else if (protocol == "UDP") {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int result = bind(sock, (SOCKADDR*)&addr, sizeof(addr));
        closesocket(sock);
        
        return result == SOCKET_ERROR;
    }

    return false;
}

std::string PortScanner::getProcessNameByPid(unsigned long pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "Unknown";
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return "Unknown";
    }

    std::string processName = "Unknown";
    do {
        if (pe32.th32ProcessID == pid) {
            std::wstring wName(pe32.szExeFile);
            processName = std::string(wName.begin(), wName.end());
            break;
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return processName;
}
