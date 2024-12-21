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
        signal(SIGTERM, signalHandler);

        // Create network client
        NetworkClient networkClient("http://localhost:8000");
        if (!networkClient.initialize()) {
            std::cerr << "Failed to initialize network client" << std::endl;
            return 1;
        }

        // Create and start log collector
        LogCollector logCollector(networkClient);
        logCollector.start();

        ProcessScanner processScanner;
        PortScanner portScanner;
        BehaviorMonitor behaviorMonitor;

        std::cout << "EDR Client started. Press Ctrl+C to stop." << std::endl;

        // Main loop
        while (running) {
            try {
                // Scan for processes
                auto processes = processScanner.scanProcesses();
                std::cout << "Found " << processes.size() << " running processes" << std::endl;
                networkClient.sendLog("INFO", "Process scan completed. Found " + std::to_string(processes.size()) + " processes", "ProcessScanner");

                // Scan for open ports
                auto ports = portScanner.scanPorts();
                std::cout << "Found " << ports.size() << " open ports" << std::endl;
                networkClient.sendLog("INFO", "Port scan completed. Found " + std::to_string(ports.size()) + " open ports", "PortScanner");

                // Check for suspicious activities
                auto activities = behaviorMonitor.checkForSuspiciousActivities();
                if (!activities.empty()) {
                    std::cout << "Found " << activities.size() << " suspicious activities" << std::endl;
                    networkClient.sendLog("WARNING", "Found " + std::to_string(activities.size()) + " suspicious activities", "BehaviorMonitor");
                    
                    // Log each suspicious activity
                    for (const auto& activity : activities) {
                        networkClient.sendLog("WARNING", 
                            "Suspicious Activity: " + activity.type + " - " + activity.description + 
                            (activity.processName.empty() ? "" : " (Process: " + activity.processName + ")"),
                            "BehaviorMonitor");
                    }
                }

                // Send data to server
                std::cout << "Sending data to server..." << std::endl;
                if (!networkClient.sendData(processes, ports, activities)) {
                    std::cerr << "Failed to send data to server" << std::endl;
                    networkClient.sendLog("ERROR", "Failed to send data to server", "main");
                } else {
                    std::cout << "Data sent successfully to server" << std::endl;
                    networkClient.sendLog("INFO", "Data sent successfully to server", "main");
                }

                // Check and send logs
                networkClient.checkAndSendLogs();

                std::cout << "Waiting 1 second before next scan..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (const std::exception& e) {
                std::cerr << "Error during scan: " << e.what() << std::endl;
                networkClient.sendLog("ERROR", std::string("Error during scan: ") + e.what(), "main");
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }

        // Cleanup
        logCollector.stop();
        std::cout << "EDR Client stopped." << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
