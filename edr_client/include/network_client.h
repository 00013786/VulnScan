#ifndef NETWORK_CLIENT_H
#define NETWORK_CLIENT_H

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <nlohmann/json.hpp>
#include "process_scanner.h"
#include "port_scanner.h"
#include "behavior_monitor.h"

using json = nlohmann::json;

#define SERVER_URL L"http://localhost:8000"

class NetworkClient {
public:
    NetworkClient(const std::string& serverUrl);
    ~NetworkClient();

    bool initialize();
    bool sendData(const std::vector<ProcessInfo>& processes, 
                 const std::vector<PortInfo>& ports,
                 const std::vector<SuspiciousActivity>& activities);
    bool executeCommand(const std::string& command, std::string& output);
    std::string createJsonPayload(const std::vector<ProcessInfo>& processes,
                                const std::vector<PortInfo>& ports,
                                const std::vector<SuspiciousActivity>& activities);

private:
    std::wstring serverUrl;
    HINTERNET hSession;
    HINTERNET hConnect;

    bool sendHttpRequest(const std::wstring& path, const std::string& data);
};

#endif // NETWORK_CLIENT_H
