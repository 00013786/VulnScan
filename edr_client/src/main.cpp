#include <iostream>
#include <string>
#include <windows.h>
#include <thread>
#include <chrono>
#include <csignal>
#include <vector>
#include <nlohmann/json.hpp>
#include "network_client.h"
#include "log_collector.h"
#include "process_scanner.h"
#include "port_scanner.h"
#include "behavior_monitor.h"

// Global flag for graceful shutdown
volatile bool running = true;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "Interrupt signal received. Shutting down..." << std::endl;
    running = false;
}

// Helper function to execute a command and get its output
bool executeCommand(const std::string& command, std::string& output) {
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return false;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    return _pclose(pipe) == 0;
}

int main() {
    try {
        // Set up signal handler
        signal(SIGINT, signalHandler);

        // Initialize components
        NetworkClient networkClient("localhost", 8000);
        ProcessScanner processScanner;
        PortScanner portScanner;
        BehaviorMonitor behaviorMonitor;

        std::cout << "EDR Client started" << std::endl;

        // Main monitoring loop
        while (running) {
            try {
                // Scan for processes and ports
                auto processes = processScanner.scanProcesses();
                auto ports = portScanner.scanPorts();
                auto suspiciousActivities = behaviorMonitor.detectSuspiciousActivities();

                // Send data to server
                if (!networkClient.sendData(processes, ports, suspiciousActivities)) {
                    std::cerr << "Failed to send data to server" << std::endl;
                }

                // Check for commands from server
                auto commands = networkClient.fetchCommands();
                for (const auto& command : commands) {
                    std::cout << "Executing command: " << command << std::endl;
                    
                    std::string output;
                    bool success = executeCommand(command, output);
                    
                    // Create log entry for command execution
                    LogEntry logEntry{
                        success ? "INFO" : "ERROR",
                        "Command execution: " + command + "\nOutput: " + output,
                        "command_executor",
                        std::chrono::system_clock::now()
                    };
                    
                    std::vector<LogEntry> logs{logEntry};
                    networkClient.sendLogs(logs);
                }

                // Sleep for a while before next scan
                std::cout << "Waiting 1 second before next scan..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (const std::exception& e) {
                std::cerr << "Error in monitoring loop: " << e.what() << std::endl;
                
                // Log the error
                LogEntry errorLog{
                    "ERROR",
                    e.what(),
                    "main_loop",
                    std::chrono::system_clock::now()
                };
                
                std::vector<LogEntry> logs{errorLog};
                networkClient.sendLogs(logs);
                
                // Sleep for a while before retrying
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        std::cout << "EDR Client shutting down..." << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
