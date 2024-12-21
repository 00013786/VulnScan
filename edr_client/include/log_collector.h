#ifndef LOG_COLLECTOR_H
#define LOG_COLLECTOR_H

#include <thread>
#include <string>
#include <windows.h>
#include <winevt.h>
#include "network_client.h"

#pragma comment(lib, "wevtapi.lib")

class LogCollector {
public:
    LogCollector(NetworkClient& networkClient);
    ~LogCollector();

    void start();
    void stop();

private:
    void collectLogs();
    void processEvent(EVT_HANDLE hEvent);

    NetworkClient& networkClient;
    std::thread collectorThread;
    bool isRunning;
};

#endif // LOG_COLLECTOR_H
