#pragma once
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

struct PortInfo {
    unsigned short port;
    std::string protocol;
    std::string state;
    std::string processName;
    DWORD pid;
};

class PortScanner {
public:
    PortScanner();
    ~PortScanner();
    std::vector<PortInfo> scanPorts();
private:
    bool initializeWinsock();
    void cleanup();
    WSADATA wsaData;
};
