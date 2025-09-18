cmake_minimum_required(VERSION 3.10.2)
project("packet_analyzer")

set(CMAKE_CXX_STANDARD 14)

# Find Android system libraries
find_library(log-lib log)
find_library(android-lib android)

# Build the shared library
add_library(packet_analyzer SHARED
    native-lib.cpp
    packet_parser.cpp
    session_manager.cpp
    socket_forwarder.cpp
)

# Add include directory for your headers
target_include_directories(packet_analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link against system libraries
target_link_libraries(packet_analyzer
    ${log-lib}
    ${android-lib}
    m
)
