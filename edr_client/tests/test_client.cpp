#include <gtest/gtest.h>
#include "../include/network_client.h"
#include "../include/process_scanner.h"
#include "../include/port_scanner.h"
#include <string>
#include <vector>

class NetworkClientTest : public ::testing::Test {
protected:
    NetworkClient* client;
    void SetUp() override {
        client = new NetworkClient("http://localhost:8000");
    }
    void TearDown() override {
        delete client;
    }
};

TEST_F(NetworkClientTest, CreateJsonPayload) {
    std::vector<ProcessInfo> processes = {
        ProcessInfo{1234, "test.exe", "C:\\test.exe", "test.exe --param"}
    };
    
    std::vector<PortInfo> ports = {
        PortInfo{8080, "TCP", "LISTEN", "test.exe", 1234}
    };
    
    std::vector<SuspiciousActivity> alerts = {
        SuspiciousActivity{
            .type = "SUSPICIOUS_PROCESS",
            .description = "Suspicious process detected",
            .pid = 1234,
            .processName = "test.exe",
            .timestamp = "2023-01-01T00:00:00Z"
        }
    };
    
    std::string payload = client->createJsonPayload(processes, ports, alerts);
    
    // Verify JSON structure
    EXPECT_TRUE(payload.find("\"processes\"") != std::string::npos);
    EXPECT_TRUE(payload.find("\"ports\"") != std::string::npos);
    EXPECT_TRUE(payload.find("\"activities\"") != std::string::npos);
    EXPECT_TRUE(payload.find("\"pid\":1234") != std::string::npos);
    EXPECT_TRUE(payload.find("\"name\":\"test.exe\"") != std::string::npos);
}

class ProcessScannerTest : public ::testing::Test {
protected:
    ProcessScanner scanner;
    void SetUp() override {}
};

TEST_F(ProcessScannerTest, ScanProcesses) {
    std::vector<ProcessInfo> processes = scanner.scanProcesses();
    EXPECT_FALSE(processes.empty());
    
    // Verify process information
    bool foundValidProcess = false;
    for (const auto& process : processes) {
        EXPECT_GT(process.pid, 0);
        EXPECT_FALSE(process.name.empty());
        
        // We might not have access to all process paths, but we should have access to at least one
        if (!process.path.empty()) {
            foundValidProcess = true;
        }
    }
    
    EXPECT_TRUE(foundValidProcess) << "Should find at least one process with full access";
}

class PortScannerTest : public ::testing::Test {
protected:
    PortScanner scanner;
    void SetUp() override {}
};

TEST_F(PortScannerTest, ScanPorts) {
    std::vector<PortInfo> ports = scanner.scanPorts();
    
    // Verify port information
    for (const auto& port : ports) {
        EXPECT_GT(port.port, 0);
        EXPECT_LE(port.port, 65535);
        EXPECT_FALSE(port.protocol.empty());
        EXPECT_FALSE(port.state.empty());
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
