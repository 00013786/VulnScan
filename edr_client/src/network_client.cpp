#include "network_client.h"
#include <winhttp.h>
#include <winsock2.h>
#include <iostream>
#include <sstream>
#include <string>
#include <codecvt>
#include <locale>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

NetworkClient::NetworkClient(const std::string& url) {
    // Convert std::string to std::wstring using wstring_convert
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    serverUrl = converter.from_bytes(url);
    hSession = NULL;
    hConnect = NULL;
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
    return hSession != NULL;
}

bool NetworkClient::sendData(const std::vector<ProcessInfo>& processes,
                           const std::vector<PortInfo>& ports,
                           const std::vector<SuspiciousActivity>& activities) {
    try {
        // Create JSON payload
        std::string payload = createJsonPayload(processes, ports, activities);
        std::cout << "Sending data to server..." << std::endl;

        return sendHttpRequest(L"/api/upload/", payload);
    }
    catch (const std::exception& e) {
        std::cerr << "Error sending data: " << e.what() << std::endl;
        return false;
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

    // Create request without WINHTTP_FLAG_SECURE flag for HTTP
    // Removed WINHTTP_FLAG_SECURE flag to allow HTTP connections
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

    // Add headers
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    if (!WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        std::cerr << "Failed to add headers. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    // Send request
    if (!WinHttpSendRequest(hRequest,
                           WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           (LPVOID)data.c_str(), data.length(),
                           data.length(), 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        return false;
    }

    WinHttpCloseHandle(hRequest);
    return true;
}

std::string NetworkClient::createJsonPayload(const std::vector<ProcessInfo>& processes,
                                           const std::vector<PortInfo>& ports,
                                           const std::vector<SuspiciousActivity>& activities) {
    json payload;
    
    // Add hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        payload["hostname"] = hostname;
    } else {
        payload["hostname"] = "unknown";
    }
    
    // Add processes
    json processArray = json::array();
    for (const auto& proc : processes) {
        json procObj;
        procObj["pid"] = proc.pid;
        procObj["name"] = proc.name;
        procObj["path"] = proc.path;
        procObj["commandLine"] = proc.commandLine;
        processArray.push_back(procObj);
    }
    payload["processes"] = processArray;

    // Add ports
    json portArray = json::array();
    for (const auto& port : ports) {
        json portObj;
        portObj["port"] = port.port;  // Changed from port_number to port
        portObj["protocol"] = port.protocol;
        portObj["state"] = port.state;
        portObj["processName"] = port.processName;
        portObj["pid"] = port.pid;
        portArray.push_back(portObj);
    }
    payload["ports"] = portArray;

    // Add alerts (renamed from activities)
    json alertArray = json::array();
    for (const auto& activity : activities) {
        json alertObj;
        alertObj["type"] = activity.type;
        alertObj["description"] = activity.description;
        alertObj["processName"] = activity.processName;
        alertObj["pid"] = activity.pid;
        alertArray.push_back(alertObj);
    }
    payload["alerts"] = alertArray;  // Changed from activities to alerts

    return payload.dump();
}

bool NetworkClient::executeCommand(const std::string& command, std::string& output) {
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
    char* cmdLineStr = _strdup(cmdLine.c_str());

    BOOL success = CreateProcessA(NULL,
        cmdLineStr,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi);

    free(cmdLineStr);

    if (!success) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        if (bytesRead == 0) break;
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
}
