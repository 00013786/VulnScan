cmake_minimum_required(VERSION 3.10)
project(edr_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add nlohmann/json
include(FetchContent)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_MakeAvailable(json)

# Add Windows libraries
if(WIN32)
    link_libraries(ws2_32 psapi iphlpapi winhttp)
endif()

set(SOURCES
    src/main.cpp
    src/process_scanner.cpp
    src/port_scanner.cpp
    src/behavior_monitor.cpp
    src/network_client.cpp
    src/log_collector.cpp
)

set(HEADERS
    include/process_scanner.h
    include/port_scanner.h
    include/behavior_monitor.h
    include/network_client.h
    include/log_collector.h
)

add_executable(edr_client 
    ${SOURCES}
    ${HEADERS}
)

target_include_directories(edr_client PRIVATE include)
target_link_libraries(edr_client PRIVATE
    nlohmann_json::nlohmann_json
    winhttp
    wevtapi
)

# Add compile definitions for include order
target_compile_definitions(edr_client PRIVATE WIN32_LEAN_AND_MEAN)
add_definitions(-D_WIN32_WINNT=0x0601)

# Add Google Test
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
)
FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()

# Add test executable
add_executable(edr_client_tests
    tests/test_client.cpp
    src/network_client.cpp
    src/process_scanner.cpp
    src/port_scanner.cpp
)

target_include_directories(edr_client_tests PRIVATE include)
target_link_libraries(edr_client_tests
    PRIVATE
    gtest_main
    nlohmann_json::nlohmann_json
    winhttp
    ws2_32
)

include(GoogleTest)
gtest_discover_tests(edr_client_tests)
