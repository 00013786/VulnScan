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

#define SERVER_URL L"http://127.0.0.1:8000"

// Path constants
const std::string UPLOAD_PATH = "/api/upload/";
const std::string LOGS_PATH = "/api/logs/upload/";
const std::string WINDOWS_LOGS_PATH = "/api/logs/windows/";

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

    bool initialize();
    bool sendData(const std::vector<ProcessInfo>& processes,
                 const std::vector<PortInfo>& ports,
                 const std::vector<SuspiciousActivity>& activities);
    
    bool sendLog(const std::string& level, const std::string& message, const std::string& source);
    void sendLog(const std::string& jsonData);
    bool hasIncomingCommand();
    nlohmann::json getCommand();
    void sendResponse(const std::string& response);
    void checkAndSendLogs();
    void uploadData(const std::string& data);
    bool executeCommand(const std::string& command, std::string& output);
    std::string createJsonPayload(const std::vector<ProcessInfo>& processes,
                                const std::vector<PortInfo>& ports,
                                const std::vector<SuspiciousActivity>& activities);

protected:
    std::string createLogsPayload(const std::vector<LogEntry>& logs);
    bool sendQueuedLogs();
    std::wstring stringToWideString(const std::string& str);

private:
    bool sendHttpRequest(const std::wstring& endpoint, const std::string& jsonData);
    bool receiveHttpResponse(HINTERNET hRequest, std::string& response);
    bool isInitialized;
    std::string serverUrl;
    std::string authToken;
    std::vector<std::string> queuedLogs;
    HINTERNET hSession;
    HINTERNET hConnect;
    std::queue<LogEntry> logQueue;
    std::mutex logMutex;
    std::chrono::system_clock::time_point lastLogSent;
    std::string hostname;
    std::string getHostname();
};

#endif // NETWORK_CLIENT_H
