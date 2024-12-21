#pragma once
#include <vector>
#include <string>
#include "port_info.h"
#include <winsock2.h>
#include <ws2tcpip.h>

class PortScanner {
public:
    PortScanner();
    ~PortScanner();
    std::vector<PortInfo> scanPorts();
    bool isPortOpen(unsigned short port, const std::string& protocol = "TCP");
    std::string getProcessNameByPid(unsigned long pid);
private:
    bool initializeWinsock();
    void cleanup();
    WSADATA wsaData;
};
