#pragma once

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <chrono>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>
#include "process_info.h"
#include "port_info.h"
#include "suspicious_activity.h"

using json = nlohmann::json;

struct LogEntry {
    std::string level;
    std::string message;
    std::string source;
    std::chrono::system_clock::time_point timestamp;
};

class NetworkClient {
public:
    NetworkClient(const std::string& serverUrl, int port);
    ~NetworkClient();

    bool sendData(const std::vector<ProcessInfo>& processes,
                 const std::vector<PortInfo>& ports,
                 const std::vector<SuspiciousActivity>& activities);

    bool sendLogs(const std::vector<LogEntry>& logs);
    std::vector<std::string> fetchCommands();

    std::string createJsonPayload(const std::vector<ProcessInfo>& processes,
                                const std::vector<PortInfo>& ports,
                                const std::vector<SuspiciousActivity>& activities);

private:
    bool sendRequest(const std::string& path,
                    const std::string& method,
                    const std::string& data,
                    std::string* response = nullptr);

    std::string createLogsPayload(const std::vector<LogEntry>& logs);
    std::wstring stringToWideString(const std::string& str);
    std::string getHostname();

    std::string serverUrl;
    int port;
    bool isInitialized;
    HINTERNET hSession;
    HINTERNET hConnect;
    std::mutex logMutex;
};
