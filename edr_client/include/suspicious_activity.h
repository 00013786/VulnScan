#pragma once
#include <string>
#include <chrono>

struct SuspiciousActivity {
    std::string type;          // Type of activity (e.g., "process_injection", "file_modification")
    std::string description;   // Detailed description of the activity
    std::string source;        // Source process/file that initiated the activity
    std::string target;        // Target process/file that was affected
    std::string severity;      // Severity level (e.g., "low", "medium", "high", "critical")
    std::chrono::system_clock::time_point timestamp;
    unsigned long sourcePid;   // PID of the source process
    unsigned long targetPid;   // PID of the target process (if applicable)
};
