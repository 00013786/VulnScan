#include <gtest/gtest.h>
#include "../include/network_client.h"
#include "../include/process_scanner.h"
#include "../include/port_scanner.h"
#include <string>
#include <vector>

class NetworkClientTest : public ::testing::Test, public NetworkClient {
public:
    NetworkClientTest() : NetworkClient("localhost", 8000) {}
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NetworkClientTest, CreateJsonPayload_Test) {
    std::vector<ProcessInfo> processes = {
        {1234, "test.exe", "C:\\test.exe", "SYSTEM", "C:\\test.exe", 0, {}, "Running", 0.0, 0}
    };

    std::vector<PortInfo> ports = {
        PortInfo{8080, "TCP", "LISTEN", "test.exe", "1234 (test.exe)"}
    };

    std::vector<SuspiciousActivity> activities = {
        SuspiciousActivity{"NETWORK", "Suspicious network connection", "test.exe", "2023-01-01 00:00:00"}
    };

    std::string payload = createJsonPayload(processes, ports, activities);

    // Verify the payload contains expected data
    EXPECT_TRUE(payload.find("test.exe") != std::string::npos);
    EXPECT_TRUE(payload.find("8080") != std::string::npos);
    EXPECT_TRUE(payload.find("NETWORK") != std::string::npos);
}

class ProcessScannerTest : public ::testing::Test {
protected:
    ProcessScanner scanner;
    void SetUp() override {}
};

TEST_F(ProcessScannerTest, ScanProcesses) {
    std::vector<ProcessInfo> processes = scanner.scanProcesses();
    EXPECT_FALSE(processes.empty());
    
    for (const auto& process : processes) {
        EXPECT_GT(process.pid, 0);
        EXPECT_FALSE(process.name.empty());
        EXPECT_FALSE(process.path.empty());
    }
}

class PortScannerTest : public ::testing::Test {
protected:
    PortScanner scanner;
    void SetUp() override {}
};

TEST_F(PortScannerTest, ScanPorts) {
    std::vector<PortInfo> ports = scanner.scanPorts();
    EXPECT_FALSE(ports.empty());
    
    for (const auto& port : ports) {
        EXPECT_GT(port.port, 0);
        EXPECT_FALSE(port.protocol.empty());
        EXPECT_FALSE(port.state.empty());
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
