#include "log_collector.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <evntcons.h>
#include <winevt.h>
#include <memory>
#include <algorithm>
#include <cctype>
#include <iomanip>

#pragma comment(lib, "wevtapi.lib")

LogCollector::LogCollector(NetworkClient& networkClient) 
    : networkClient(networkClient), isRunning(false) {
}

LogCollector::~LogCollector() {
    stop();
}

void LogCollector::start() {
    if (isRunning) {
        return;
    }

    isRunning = true;
    collectorThread = std::thread(&LogCollector::collectLogs, this);
}

void LogCollector::stop() {
    if (!isRunning) {
        return;
    }

    isRunning = false;
    if (collectorThread.joinable()) {
        collectorThread.join();
    }
}

void LogCollector::collectLogs() {
    EVT_HANDLE hSubscription = NULL;

    try {
        // Subscribe to all events from the Security channel
        hSubscription = EvtSubscribe(
            NULL,                     // Session
            NULL,                     // Signal event
            L"Security",              // Channel path
            L"*",                     // Query
            NULL,                     // Bookmark
            this,                     // Context
            [](EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent) -> DWORD {
                if (action == EvtSubscribeActionDeliver) {
                    LogCollector* collector = static_cast<LogCollector*>(context);
                    collector->processEvent(hEvent);
                }
                return ERROR_SUCCESS;
            },
            EvtSubscribeToFutureEvents  // Flags
        );

        if (!hSubscription) {
            throw std::runtime_error("Failed to subscribe to events");
        }

        // Keep the subscription active until stop is called
        while (isRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in log collection: " << e.what() << std::endl;
    }

    if (hSubscription) {
        EvtClose(hSubscription);
    }
}

void LogCollector::processEvent(EVT_HANDLE hEvent) {
    try {
        // Get event XML
        DWORD bufferSize = 0;
        DWORD bufferUsed = 0;
        DWORD propertyCount = 0;
        
        // Get required buffer size
        EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferUsed, &propertyCount);
        
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            throw std::runtime_error("Failed to get buffer size for event");
        }

        std::vector<wchar_t> buffer(bufferUsed);
        
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
            throw std::runtime_error("Failed to render event");
        }

        // Create log entry
        LogEntry logEntry;
        logEntry.level = "INFO";
        logEntry.message = std::string(buffer.begin(), buffer.end());
        logEntry.source = "windows_events";
        logEntry.timestamp = std::chrono::system_clock::now();

        // Send log entry
        std::vector<LogEntry> logs{logEntry};
        networkClient.sendLogs(logs);
    }
    catch (const std::exception& e) {
        std::cerr << "Error processing event: " << e.what() << std::endl;
    }
}
