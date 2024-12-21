#pragma once
#include <string>

struct PortInfo {
    unsigned short port;
    std::string protocol;  // TCP or UDP
    std::string state;     // LISTENING, ESTABLISHED, etc.
    std::string localAddress;
    std::string remoteAddress;
    unsigned long pid;
    std::string processName;
};
