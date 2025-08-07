cmake_minimum_required(VERSION 3.10.2)

project("packet_analyzer")

set(CMAKE_CXX_STANDARD 14)

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Set libpcap paths based on architecture
if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(LIBPCAP_INCLUDE_DIR "C:/libpcap-android/output/arm64-v8a/include")
    set(LIBPCAP_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/arm64-v8a/libpcap.so")
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(LIBPCAP_INCLUDE_DIR "C:/libpcap-android/output/armeabi-v7a/include")
    set(LIBPCAP_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/armeabi-v7a/libpcap.a")
else()
    message(FATAL_ERROR "Unsupported architecture: ${ANDROID_ABI}")
endif()

# Include libpcap headers
include_directories(${LIBPCAP_INCLUDE_DIR})

# Add pcap library
if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    add_library(pcap SHARED IMPORTED)
else()
    add_library(pcap STATIC IMPORTED)
endif()

set_target_properties(pcap PROPERTIES IMPORTED_LOCATION ${LIBPCAP_LIB_PATH})

# Add your library
add_library(packet_analyzer SHARED
    native-lib.cpp
    packet_parser.cpp
    session_manager.cpp
    socket_forwarder.cpp
)

# Link libraries
target_link_libraries(packet_analyzer
    pcap
    ${log-lib}
    ${android-lib}
)
