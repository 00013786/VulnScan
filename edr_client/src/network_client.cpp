#include "network_client.h"
#include <winhttp.h>
#include <winsock2.h>
#include <iostream>
#include <sstream>
#include <string>
#include <codecvt>
#include <locale>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

std::mutex logMutex;
std::chrono::system_clock::time_point lastLogSent;

NetworkClient::NetworkClient(const std::string& serverUrl) {
    // Convert server URL to wide string
    std::wstring wServerUrl(serverUrl.begin(), serverUrl.end());
    this->serverUrl = wServerUrl;
    
    // Get hostname
    char hostnameBuffer[256];
    if (gethostname(hostnameBuffer, sizeof(hostnameBuffer)) == 0) {
        hostname = hostnameBuffer;
    } else {
        hostname = "unknown";
    }
    
    lastLogSent = std::chrono::system_clock::now();
    if (!initialize()) {
        std::cerr << "Failed to initialize network client" << std::endl;
        throw std::runtime_error("Failed to initialize network client");
    }
}

NetworkClient::~NetworkClient() {
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

bool NetworkClient::initialize() {
    hSession = WinHttpOpen(L"EDR Client/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          0);
    if (hSession == NULL) {
        std::cerr << "Failed to create WinHTTP session" << std::endl;
        return false;
    }
    return true;
}

bool NetworkClient::sendData(const std::vector<ProcessInfo>& processes,
               const std::vector<PortInfo>& ports,
               const std::vector<SuspiciousActivity>& activities) {
    try {
        std::string jsonPayload = createJsonPayload(processes, ports, activities);
        return sendHttpRequest(UPLOAD_PATH, jsonPayload);
    } catch (const std::exception& e) {
        std::cerr << "Error creating or sending data payload: " << e.what() << std::endl;
        return false;
    }
}

bool NetworkClient::sendLog(const std::string& level, const std::string& message, const std::string& source) {
    try {
        std::lock_guard<std::mutex> lock(logMutex);
        
        LogEntry entry{
            level,
            message,
            source,
            std::chrono::system_clock::now()
        };
        
        logQueue.push(entry);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error queueing log: " << e.what() << std::endl;
        return false;
    }
}

bool NetworkClient::checkAndSendLogs() {
    try {
        auto now = std::chrono::system_clock::now();
        if (std::chrono::duration_cast<std::chrono::minutes>(now - lastLogSent).count() >= 1) {
            return sendQueuedLogs();
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error checking/sending logs: " << e.what() << std::endl;
        return false;
    }
}

bool NetworkClient::sendQueuedLogs() {
    std::lock_guard<std::mutex> lock(logMutex);
    if (logQueue.empty()) {
        return true;
    }

    try {
        std::vector<LogEntry> logs;
        while (!logQueue.empty()) {
            logs.push_back(logQueue.front());
            logQueue.pop();
        }

        std::string jsonPayload = createLogsPayload(logs);
        bool success = sendHttpRequest(LOGS_PATH, jsonPayload);
        if (success) {
            lastLogSent = std::chrono::system_clock::now();
            std::cout << "Successfully sent " << logs.size() << " logs to server" << std::endl;
        } else {
            std::cerr << "Failed to send logs to server" << std::endl;
            // Put logs back in queue if send failed
            for (const auto& log : logs) {
                logQueue.push(log);
            }
        }
        return success;
    } catch (const std::exception& e) {
        std::cerr << "Error sending queued logs: " << e.what() << std::endl;
        return false;
    }
}

std::string NetworkClient::createLogsPayload(const std::vector<LogEntry>& logs) {
    try {
        json j;
        j["logs"] = json::array();

        for (const auto& log : logs) {
            json log_entry;
            log_entry["level"] = log.level;
            log_entry["message"] = log.message;
            log_entry["source"] = log.source;
            log_entry["hostname"] = hostname;
            
            // Convert timestamp to Unix timestamp
            auto timestamp = std::chrono::system_clock::to_time_t(log.timestamp);
            log_entry["timestamp"] = timestamp;

            j["logs"].push_back(log_entry);
        }

        return j.dump();
    } catch (const std::exception& e) {
        std::cerr << "Error creating logs payload: " << e.what() << std::endl;
        throw;
    }
}

bool NetworkClient::sendHttpRequest(const std::wstring& path, const std::string& data) {
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    
    wchar_t scheme[256] = L"";
    wchar_t host[256] = L"";
    wchar_t urlPath[1024] = L"";
    
    urlComp.lpszScheme = scheme;
    urlComp.dwSchemeLength = sizeof(scheme) / sizeof(scheme[0]);
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = sizeof(host) / sizeof(host[0]);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(urlPath[0]);

    if (!WinHttpCrackUrl(serverUrl.c_str(), 0, 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!hSession) {
        if (!initialize()) {
            return false;
        }
    }

    hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) {
        std::cerr << "Failed to connect. Error: " << GetLastError() << std::endl;
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                          L"POST",
                                          path.c_str(),
                                          NULL,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          0);
    if (!hRequest) {
        std::cerr << "Failed to create request. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPCWSTR headers = L"Content-Type: application/json\r\n";
    if (!WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        std::cerr << "Failed to add headers. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    if (!WinHttpSendRequest(hRequest,
                           WINHTTP_NO_ADDITIONAL_HEADERS,
                           0,
                           (LPVOID)data.c_str(),
                           data.length(),
                           data.length(),
                           0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &statusCode,
                       &statusCodeSize,
                       WINHTTP_NO_HEADER_INDEX);

    WinHttpCloseHandle(hRequest);

    return (statusCode >= 200 && statusCode < 300);
}

std::string NetworkClient::createJsonPayload(const std::vector<ProcessInfo>& processes,
                               const std::vector<PortInfo>& ports,
                               const std::vector<SuspiciousActivity>& activities) {
    try {
        json payload;
        
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            payload["hostname"] = hostname;
        } else {
            payload["hostname"] = "unknown";
        }

        json processArray = json::array();
        for (const auto& process : processes) {
            json processObj;
            processObj["pid"] = process.pid;
            processObj["name"] = process.name;
            processObj["path"] = process.path;
            processObj["command_line"] = process.commandLine;
            processArray.push_back(processObj);
        }
        payload["processes"] = processArray;

        json portArray = json::array();
        for (const auto& port : ports) {
            json portObj;
            portObj["port"] = port.port;
            portObj["protocol"] = port.protocol;
            portObj["state"] = port.state;
            portObj["process_id"] = port.pid;
            portObj["process_name"] = port.processName;
            portArray.push_back(portObj);
        }
        payload["ports"] = portArray;

        json activityArray = json::array();
        for (const auto& activity : activities) {
            json activityObj;
            activityObj["type"] = activity.type;
            activityObj["description"] = activity.description;
            activityObj["process_name"] = activity.processName;
            activityObj["process_id"] = activity.pid;
            activityArray.push_back(activityObj);
        }
        payload["suspicious_activities"] = activityArray;

        return payload.dump();
    } catch (const std::exception& e) {
        std::cerr << "Error creating JSON payload: " << e.what() << std::endl;
        throw;
    }
}

bool NetworkClient::executeCommand(const std::string& command, std::string& output) {
    try {
        output.clear();
        
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        HANDLE hReadPipe, hWritePipe;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
            return false;
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hWritePipe;
        si.hStdOutput = hWritePipe;
        si.dwFlags |= STARTF_USESTDHANDLES;
        ZeroMemory(&pi, sizeof(pi));

        std::string cmdLine = "cmd.exe /c " + command;
        if (!CreateProcessA(NULL,
                           const_cast<LPSTR>(cmdLine.c_str()),
                           NULL,
                           NULL,
                           TRUE,
                           CREATE_NO_WINDOW,
                           NULL,
                           NULL,
                           &si,
                           &pi)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return false;
        }

        CloseHandle(hWritePipe);

        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);

        return exitCode == 0;
    } catch (const std::exception& e) {
        std::cerr << "Error executing command: " << e.what() << std::endl;
        return false;
    }
}
