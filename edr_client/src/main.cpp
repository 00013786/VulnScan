#include <iostream>
#include <string>
#include <windows.h>
#include <thread>
#include <chrono>
#include <csignal>
#include "network_client.h"
#include "log_collector.h"
#include "process_scanner.h"
#include "port_scanner.h"
#include "behavior_monitor.h"
#include "nlohmann/json.hpp"

// Global flag for graceful shutdown
volatile bool running = true;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "Interrupt signal received. Shutting down..." << std::endl;
    running = false;
}

int main() {
    try {
        // Set up signal handler
        signal(SIGINT, signalHandler);

        // Initialize components
        ProcessScanner processScanner;
        NetworkClient networkClient("http://localhost:8000");
        BehaviorMonitor behaviorMonitor;
        PortScanner portScanner;

        if (!networkClient.initialize()) {
            std::cerr << "Failed to initialize network client" << std::endl;
            return 1;
        }

        // Function to handle commands
        auto handleCommand = [&](const nlohmann::json& command) {
            try {
                std::string action = command["action"];
                if (action == "scan") {
                    // Handle scan command
                    auto processes = processScanner.scanProcesses();
                    // Process and send results
                }
                else if (action == "kill_process") {
                    if (!command.contains("process_id")) {
                        std::cerr << "Missing process_id in kill command" << std::endl;
                        return;
                    }
                    
                    DWORD processId = command["process_id"];
                    bool success = processScanner.killProcess(processId);
                    
                    nlohmann::json response;
                    response["success"] = success;
                    if (!success) {
                        response["error"] = "Failed to terminate process";
                    }
                    
                    networkClient.sendResponse(response.dump());
                }
                else if (action == "verify_process") {
                    if (!command.contains("process_id")) {
                        std::cerr << "Missing process_id in verify command" << std::endl;
                        return;
                    }
                    
                    DWORD processId = command["process_id"];
                    bool isRunning = processScanner.isProcessRunning(processId);
                    
                    nlohmann::json response;
                    response["is_running"] = isRunning;
                    networkClient.sendResponse(response.dump());
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error handling command: " << e.what() << std::endl;
            }
        };

        // Main loop
        while (running) {
            try {
                // Scan processes
                auto processes = processScanner.scanProcesses();

                // Convert to JSON
                nlohmann::json j = nlohmann::json::array();
                for (const auto& process : processes) {
                    nlohmann::json processJson;
                    processJson["pid"] = process.pid;
                    processJson["name"] = process.name;
                    processJson["path"] = process.path;
                    processJson["owner"] = process.owner;
                    j.push_back(processJson);
                }

                // Send to server
                networkClient.sendLog(j.dump());

                // Check and send logs
                networkClient.checkAndSendLogs();

                // Handle incoming commands
                if (networkClient.hasIncomingCommand()) {
                    nlohmann::json command = networkClient.getCommand();
                    handleCommand(command);
                }

                std::cout << "Waiting 1 second before next scan..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (const std::exception& e) {
                std::cerr << "Error in main loop: " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
