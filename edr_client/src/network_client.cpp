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

NetworkClient::NetworkClient(const std::string& url) : serverUrl(url), isInitialized(false), hSession(NULL), hConnect(NULL) {
    // Initialize WinHTTP
    hSession = WinHttpOpen(
        L"EDR Client/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        throw std::runtime_error("Failed to initialize WinHTTP session");
    }
}

NetworkClient::~NetworkClient() {
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
    }
}

bool NetworkClient::initialize() {
    if (isInitialized) {
        return true;
    }

    try {
        // Convert URL to wide string for WinHTTP
        std::wstring wideUrl = stringToWideString(serverUrl);

        // Parse URL and connect
        URL_COMPONENTS urlComp = { 0 };
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = -1;
        urlComp.dwHostNameLength = -1;
        urlComp.dwUrlPathLength = -1;

        if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &urlComp)) {
            std::cerr << "Failed to parse URL. Error: " << GetLastError() << std::endl;
            return false;
        }

        hConnect = WinHttpConnect(
            hSession,
            std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength).c_str(),
            urlComp.nPort,
            0
        );

        if (!hConnect) {
            std::cerr << "Failed to connect to server. Error: " << GetLastError() << std::endl;
            return false;
        }

        isInitialized = true;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error initializing network client: " << e.what() << std::endl;
        return false;
    }
}

void NetworkClient::checkAndSendLogs() {
    if (!isInitialized) {
        return;
    }
    sendQueuedLogs();
}

void NetworkClient::sendLog(const std::string& jsonData) {
    if (!isInitialized) {
        std::cerr << "Client not initialized" << std::endl;
        return;
    }

    try {
        std::string endpoint = serverUrl + "/api/logs/windows/";
        std::string headers = "Content-Type: application/json\r\n";
        headers += "Authorization: Token " + authToken + "\r\n";

        bool success = sendHttpRequest(stringToWideString(endpoint), jsonData);
        if (!success) {
            std::cerr << "Failed to send log data" << std::endl;
            queuedLogs.push_back(jsonData);
        } else {
            std::cout << "Successfully sent log data" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error sending log: " << e.what() << std::endl;
        queuedLogs.push_back(jsonData);
    }
}

bool NetworkClient::sendHttpRequest(const std::wstring& path, const std::string& data) {
    if (!isInitialized) {
        std::cerr << "Client not initialized. Call initialize() first." << std::endl;
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        std::cerr << "Failed to open request. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Add security flags to handle SSL/TLS
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))) {
        std::cerr << "Failed to set security options. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!authToken.empty() && authToken != "your_auth_token_here") {
        headers += L"Authorization: Token " + stringToWideString(authToken) + L"\r\n";
    }

    bool success = WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        -1L,
        (LPVOID)data.c_str(),
        data.length(),
        data.length(),
        0
    );

    if (!success) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    success = WinHttpReceiveResponse(hRequest, NULL);
    if (!success) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    // Get the HTTP status code
    DWORD statusCode = 0;
    DWORD size = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &size,
        WINHTTP_NO_HEADER_INDEX);

    if (statusCode < 200 || statusCode >= 300) {
        std::cerr << "Server returned error status code: " << statusCode << std::endl;
        
        // Read and log response body for error details
        DWORD bytesAvailable;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            std::vector<char> buffer(bytesAvailable + 1);
            DWORD bytesRead;
            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                buffer[bytesRead] = '\0';
                std::cerr << "Error response: " << buffer.data() << std::endl;
            }
        }
        
        WinHttpCloseHandle(hRequest);
        return false;
    }

    WinHttpCloseHandle(hRequest);
    return true;
}

bool NetworkClient::sendQueuedLogs() {
    if (queuedLogs.empty()) {
        return true;
    }

    std::vector<std::string> failedLogs;
    for (const auto& log : queuedLogs) {
        if (!sendHttpRequest(stringToWideString("/api/logs/windows/"), log)) {
            failedLogs.push_back(log);
        }
    }

    queuedLogs = failedLogs;
    return queuedLogs.empty();
}

std::wstring NetworkClient::stringToWideString(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::vector<wchar_t> buf(size);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, buf.data(), size);
    return std::wstring(buf.data());
}

std::string NetworkClient::getHostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown-host";
}

bool NetworkClient::sendData(const std::vector<ProcessInfo>& processes,
               const std::vector<PortInfo>& ports,
               const std::vector<SuspiciousActivity>& activities) {
    try {
        std::string jsonPayload = createJsonPayload(processes, ports, activities);
        return sendHttpRequest(stringToWideString(UPLOAD_PATH), jsonPayload);
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
