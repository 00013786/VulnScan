#include <iostream>
#include <chrono>
#include <thread>
#include "process_scanner.h"
#include "port_scanner.h"
#include "behavior_monitor.h"
#include "network_client.h"

int main() {
    try {
        ProcessScanner processScanner;
        PortScanner portScanner;
        BehaviorMonitor behaviorMonitor;
        NetworkClient networkClient("http://localhost:8000/api/upload/");

        std::cout << "EDR Client started. Connecting to server..." << std::endl;

        while (true) {
            try {
                // Scan for processes
                auto processes = processScanner.scanProcesses();
                std::cout << "Found " << processes.size() << " running processes" << std::endl;

                // Scan for open ports
                auto ports = portScanner.scanPorts();
                std::cout << "Found " << ports.size() << " open ports" << std::endl;

                // Check for suspicious activities
                auto activities = behaviorMonitor.checkForSuspiciousActivities();
                if (!activities.empty()) {
                    std::cout << "Found " << activities.size() << " suspicious activities" << std::endl;
                }

                // Send data to server
                if (!networkClient.sendData(processes, ports, activities)) {
                    std::cerr << "Failed to send data to server" << std::endl;
                } else {
                    std::cout << "Data sent successfully to server" << std::endl;
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error during scan cycle: " << e.what() << std::endl;
            }

            // Wait for 15 seconds before next scan
            std::cout << "Waiting 15 seconds before next scan..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
