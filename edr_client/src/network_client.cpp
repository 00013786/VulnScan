#include "network_client.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <memory>
#include <algorithm>
#include <cctype>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

std::mutex logMutex;
std::chrono::system_clock::time_point lastLogSent;

NetworkClient::NetworkClient(const std::string& serverUrl, int port) 
    : serverUrl(serverUrl), port(port), isInitialized(false), hSession(NULL), hConnect(NULL) {
    
    // Initialize WinHTTP
    hSession = WinHttpOpen(L"EDR Client/1.0", 
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, 
                          WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        throw std::runtime_error("Failed to initialize WinHTTP session");
    }

    // Create connection handle
    std::wstring wideUrl = stringToWideString(serverUrl);
    hConnect = WinHttpConnect(hSession, wideUrl.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to connect to server");
    }
    
    isInitialized = true;
}

NetworkClient::~NetworkClient() {
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
    }
}

bool NetworkClient::sendData(const std::vector<ProcessInfo>& processes,
                           const std::vector<PortInfo>& ports,
                           const std::vector<SuspiciousActivity>& activities) {
    try {
        std::string jsonPayload = createJsonPayload(processes, ports, activities);
        std::cout << "Sending data payload: " << jsonPayload << std::endl;
        return sendRequest("/api/upload/", "POST", jsonPayload);
    }
    catch (const std::exception& e) {
        std::cerr << "Error sending data: " << e.what() << std::endl;
        return false;
    }
}

bool NetworkClient::sendLogs(const std::vector<LogEntry>& logs) {
    try {
        std::string jsonPayload = createLogsPayload(logs);
        std::cout << "Sending logs payload: " << jsonPayload << std::endl;
        return sendRequest("/api/logs/upload/", "POST", jsonPayload);
    }
    catch (const std::exception& e) {
        std::cerr << "Error sending logs: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> NetworkClient::fetchCommands() {
    std::vector<std::string> commands;
    try {
        // Create JSON payload with hostname
        json payload;
        payload["hostname"] = getHostname();
        std::string jsonPayload = payload.dump();
        
        std::cout << "Sending command request payload: " << jsonPayload << std::endl;

        // Send POST request
        std::string response;
        if (sendRequest("/api/commands/pending/", "POST", jsonPayload, &response)) {
            std::cout << "Received response: " << response << std::endl;
            
            // Parse response
            try {
                json responseJson = json::parse(response);
                if (responseJson.contains("commands") && responseJson["commands"].is_array()) {
                    for (const auto& cmd : responseJson["commands"]) {
                        if (cmd.contains("command")) {
                            commands.push_back(cmd["command"].get<std::string>());
                        }
                    }
                }
            } catch (const json::parse_error& e) {
                std::cerr << "JSON parse error: " << e.what() << std::endl;
                std::cerr << "Response data: " << response << std::endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error fetching commands: " << e.what() << std::endl;
    }
    return commands;
}

bool NetworkClient::sendRequest(const std::string& path, 
                              const std::string& method,
                              const std::string& data,
                              std::string* response) {
    if (!isInitialized) {
        std::cerr << "Client not initialized" << std::endl;
        return false;
    }

    if (!hSession || !hConnect) {
        std::cerr << "WinHTTP session not initialized" << std::endl;
        return false;
    }

    // Convert path to wide string
    std::wstring wPath(path.begin(), path.end());
    
    // Create request handle
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                          method == "POST" ? L"POST" : L"GET",
                                          wPath.c_str(),
                                          NULL,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          0);  
    if (!hRequest) {
        std::cerr << "Failed to create request" << std::endl;
        return false;
    }

    // Add headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    // Add authentication header if we have a token
    std::string authToken = "3449e856-63f6-4217-a03a-64a216e9d501";
    if (!authToken.empty()) {
        headers += L"Authorization: Token " + stringToWideString(authToken) + L"\r\n";
    }
    
    if (!WinHttpAddRequestHeaders(hRequest, 
                                headers.c_str(),
                                -1L,
                                WINHTTP_ADDREQ_FLAG_ADD)) {
        WinHttpCloseHandle(hRequest);
        std::cerr << "Failed to add headers" << std::endl;
        return false;
    }

    // Send request
    BOOL bResults = WinHttpSendRequest(hRequest,
                                     WINHTTP_NO_ADDITIONAL_HEADERS,
                                     0,
                                     method == "POST" ? (LPVOID)data.c_str() : WINHTTP_NO_REQUEST_DATA,
                                     method == "POST" ? data.length() : 0,
                                     method == "POST" ? data.length() : 0,
                                     0);

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    // Get status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    if (bResults) {
        WinHttpQueryHeaders(hRequest,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,
                           &statusCode,
                           &statusCodeSize,
                           WINHTTP_NO_HEADER_INDEX);
        
        std::cout << "HTTP Status Code: " << statusCode << std::endl;
        
        if (statusCode != 200) {
            std::cerr << "Server returned error status: " << statusCode << std::endl;
            bResults = FALSE;
        }
    }

    // Handle response if needed
    if (bResults && response != nullptr) {
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        std::string responseData;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                std::cerr << "Error in WinHttpQueryDataAvailable" << std::endl;
                break;
            }

            if (dwSize == 0) {
                break;
            }

            std::vector<char> buffer(dwSize + 1);
            if (!WinHttpReadData(hRequest, 
                               static_cast<LPVOID>(buffer.data()),
                               dwSize, &dwDownloaded)) {
                std::cerr << "Error in WinHttpReadData" << std::endl;
                break;
            }

            buffer[dwDownloaded] = '\0';
            responseData += buffer.data();
        } while (dwSize > 0);

        *response = responseData;
    }

    // Cleanup
    WinHttpCloseHandle(hRequest);

    return bResults != FALSE;
}

std::string NetworkClient::createJsonPayload(const std::vector<ProcessInfo>& processes,
                                           const std::vector<PortInfo>& ports,
                                           const std::vector<SuspiciousActivity>& activities) {
    json payload;

    // Add hostname
    payload["hostname"] = getHostname();

    // Add processes
    json processesArray = json::array();
    for (const auto& process : processes) {
        json processObj;
        processObj["pid"] = process.pid;
        processObj["name"] = process.name;
        processObj["path"] = process.path;
        processObj["owner"] = process.owner;
        processObj["commandLine"] = process.commandLine;
        processObj["parent_pid"] = process.parentPid;
        processObj["status"] = process.status;
        processObj["cpu_usage"] = process.cpuUsage;
        processObj["memory_usage"] = process.memoryUsage;

        // Add modules
        json modulesArray = json::array();
        for (const auto& module : process.modules) {
            modulesArray.push_back(module);
        }
        processObj["modules"] = modulesArray;

        processesArray.push_back(processObj);
    }
    payload["processes"] = processesArray;

    // Add ports
    json portsArray = json::array();
    for (const auto& port : ports) {
        json portObj;
        portObj["port"] = port.port;
        portObj["protocol"] = port.protocol;
        portObj["state"] = port.state;
        portObj["processName"] = port.processName;
        portObj["pid"] = port.pid;
        portsArray.push_back(portObj);
    }
    payload["ports"] = portsArray;

    // Add suspicious activities as alerts
    json alertsArray = json::array();
    for (const auto& activity : activities) {
        json alertObj;
        alertObj["type"] = activity.type;
        alertObj["description"] = activity.description;
        alertObj["processName"] = activity.source;
        alertObj["pid"] = activity.sourcePid;
        alertObj["severity"] = activity.severity;
        
        // Convert timestamp to string
        auto timepoint = activity.timestamp;
        auto time_t = std::chrono::system_clock::to_time_t(timepoint);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        alertObj["timestamp"] = ss.str();

        alertsArray.push_back(alertObj);
    }
    payload["alerts"] = alertsArray;

    return payload.dump();
}

std::string NetworkClient::createLogsPayload(const std::vector<LogEntry>& logs) {
    json payload;
    payload["hostname"] = getHostname();

    json logsArray = json::array();
    for (const auto& log : logs) {
        json logObj;
        logObj["level"] = log.level;
        logObj["source"] = log.source;
        logObj["message"] = log.message;
        
        auto timepoint = log.timestamp;
        auto time_t = std::chrono::system_clock::to_time_t(timepoint);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        logObj["timestamp"] = ss.str();
        
        logsArray.push_back(logObj);
    }
    payload["logs"] = logsArray;

    return payload.dump();
}

std::wstring NetworkClient::stringToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string NetworkClient::getHostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
}
