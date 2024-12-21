#ifndef NETWORK_CLIENT_H
#define NETWORK_CLIENT_H

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <nlohmann/json.hpp>
#include <queue>
#include <mutex>
#include <chrono>
#include "process_scanner.h"
#include "port_scanner.h"
#include "behavior_monitor.h"

using json = nlohmann::json;

#define SERVER_URL L"http://localhost:8000"
#define UPLOAD_PATH L"/api/upload/"
#define LOGS_PATH L"/api/logs/upload/"

struct LogEntry {
    std::string level;
    std::string message;
    std::string source;
    std::chrono::system_clock::time_point timestamp;
};

class NetworkClient {
    friend class NetworkClientTest;
public:
    NetworkClient(const std::string& serverUrl);
    ~NetworkClient();

    bool sendData(const std::vector<ProcessInfo>& processes,
                 const std::vector<PortInfo>& ports,
                 const std::vector<SuspiciousActivity>& activities);
    
    bool sendLog(const std::string& level, const std::string& message, const std::string& source);
    bool executeCommand(const std::string& command, std::string& output);
    bool checkAndSendLogs();

protected:
    std::string createJsonPayload(const std::vector<ProcessInfo>& processes,
                               const std::vector<PortInfo>& ports,
                               const std::vector<SuspiciousActivity>& activities);
    std::string createLogsPayload(const std::vector<LogEntry>& logs);

private:
    bool initialize();
    bool sendHttpRequest(const std::wstring& path, const std::string& data);
    bool sendQueuedLogs();

    std::wstring serverUrl;
    HINTERNET hSession;
    HINTERNET hConnect;
    std::queue<LogEntry> logQueue;
    std::mutex logMutex;
    std::chrono::system_clock::time_point lastLogSent;
    std::string hostname;
};

#endif // NETWORK_CLIENT_H
