#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <windows.h>
#include <winevt.h>
#include <iostream>
#include "network_client.h"

#pragma comment(lib, "wevtapi.lib")

class LogCollector {
public:
    LogCollector(NetworkClient& client);
    ~LogCollector();

    void start();
    void stop();

private:
    void collectLogs();
    void processEvent(EVT_HANDLE hEvent);
    
    std::string getEventTime(EVT_HANDLE hEvent);
    std::string getEventProvider(EVT_HANDLE hEvent);
    std::string getEventLevel(EVT_HANDLE hEvent);
    std::string getEventId(EVT_HANDLE hEvent);
    std::string getEventMessage(EVT_HANDLE hEvent);
    std::wstring stringToWideString(const std::string& str);

    NetworkClient& networkClient;
    std::atomic<bool> running;
    std::thread collectorThread;
};
