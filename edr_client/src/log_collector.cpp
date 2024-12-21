#include "../include/log_collector.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <iostream>

LogCollector::LogCollector(NetworkClient& client) : networkClient(client), running(false) {
}

LogCollector::~LogCollector() {
    stop();
}

void LogCollector::start() {
    if (running) {
        return;
    }

    running = true;
    collectorThread = std::thread(&LogCollector::collectLogs, this);
}

void LogCollector::stop() {
    running = false;
    if (collectorThread.joinable()) {
        collectorThread.join();
    }
}

void LogCollector::collectLogs() {
    EVT_HANDLE hSubscription = NULL;

    try {
        // Subscribe to Security, System, and Application logs
        const wchar_t* channels[] = {
            L"System",            // Start with System logs first
            L"Application",       // Then Application logs
            L"Security"          // Security logs might require elevated privileges
        };

        DWORD status = ERROR_SUCCESS;
        EVT_HANDLE subscription = NULL;

        for (const auto& channel : channels) {
            // Create subscription for real-time events
            subscription = EvtSubscribe(
                NULL,                           // Local computer
                NULL,                           // Signal event
                channel,                        // Channel path
                L"*",                          // Query - all events
                NULL,                           // Bookmark
                (PVOID)this,                    // Context
                [](EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent) -> DWORD {
                    if (action == EvtSubscribeActionDeliver) {
                        LogCollector* collector = static_cast<LogCollector*>(context);
                        collector->processEvent(hEvent);
                    }
                    return ERROR_SUCCESS;
                },
                EvtSubscribeToFutureEvents    // Only get new events
            );

            if (subscription == NULL) {
                DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED) {
                    std::cerr << "Access denied for " << (channel == L"Security" ? "Security" : 
                                                        channel == L"System" ? "System" : "Application") 
                             << " log. Try running as administrator." << std::endl;
                } else {
                    std::cerr << "Failed to subscribe to " << (channel == L"Security" ? "Security" : 
                                                             channel == L"System" ? "System" : "Application")
                             << " log. Error: " << error << std::endl;
                }
            } else {
                std::cout << "Successfully subscribed to " << (channel == L"Security" ? "Security" : 
                                                             channel == L"System" ? "System" : "Application")
                         << " log" << std::endl;
            }
        }

        // Keep thread running
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Cleanup subscriptions
        if (subscription) {
            EvtClose(subscription);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in log collection: " << e.what() << std::endl;
    }
}

void LogCollector::processEvent(EVT_HANDLE hEvent) {
    try {
        if (hEvent) {
            // Create log entry
            nlohmann::json logEntry;
            logEntry["level"] = getEventLevel(hEvent);
            logEntry["message"] = getEventMessage(hEvent);
            logEntry["source"] = getEventProvider(hEvent) + " (Event ID: " + getEventId(hEvent) + ")";
            logEntry["event_id"] = getEventId(hEvent);
            logEntry["provider"] = getEventProvider(hEvent);
            logEntry["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            // Create logs array
            nlohmann::json logsArray = nlohmann::json::array();
            logsArray.push_back(logEntry);

            // Create final payload
            nlohmann::json payload;
            char hostname[256];
            if (gethostname(hostname, sizeof(hostname)) == 0) {
                payload["hostname"] = std::string(hostname);
            } else {
                payload["hostname"] = "unknown-host";
            }
            payload["logs"] = logsArray;

            networkClient.sendLog(payload.dump());
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error processing event: " << e.what() << std::endl;
    }
}

std::string LogCollector::getEventTime(EVT_HANDLE hEvent) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    std::ostringstream oss;
    oss << std::setfill('0')
        << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << " "
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond;
    return oss.str();
}

std::string LogCollector::getEventProvider(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD propertyCount = 0;
    PEVT_VARIANT properties = nullptr;
    std::string result = "unknown";

    // Get the required buffer size
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferSize, &propertyCount)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            LPWSTR buffer = (LPWSTR)malloc(bufferSize);
            if (buffer) {
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer, &bufferSize, &propertyCount)) {
                    std::wstring wstr(buffer);
                    result = std::string(wstr.begin(), wstr.end());
                }
                free(buffer);
            }
        }
    }

    return result;
}

std::string LogCollector::getEventLevel(EVT_HANDLE hEvent) {
    DWORD level = 0;
    DWORD bufferSize = sizeof(DWORD);
    DWORD propertyCount = 0;
    
    if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, &level, &bufferSize, &propertyCount)) {
        switch (level) {
            case 1: return "Critical";
            case 2: return "Error";
            case 3: return "Warning";
            case 4: return "Information";
            case 5: return "Verbose";
            default: return "Unknown";
        }
    }

    return "Unknown";
}

std::string LogCollector::getEventId(EVT_HANDLE hEvent) {
    DWORD eventId = 0;
    DWORD bufferSize = sizeof(DWORD);
    DWORD propertyCount = 0;
    
    if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, &eventId, &bufferSize, &propertyCount)) {
        return std::to_string(eventId);
    }

    return "0";
}

std::string LogCollector::getEventMessage(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD propertyCount = 0;
    std::string result = "No message available";

    // Get required buffer size
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferSize, &propertyCount)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            LPWSTR buffer = (LPWSTR)malloc(bufferSize);
            if (buffer) {
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer, &bufferSize, &propertyCount)) {
                    std::wstring wstr(buffer);
                    result = std::string(wstr.begin(), wstr.end());
                }
                free(buffer);
            }
        }
    }

    return result;
}

std::wstring LogCollector::stringToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
