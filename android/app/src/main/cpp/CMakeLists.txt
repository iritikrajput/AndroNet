cmake_minimum_required(VERSION 3.10.2)
project("packet_analyzer")

set(CMAKE_CXX_STANDARD 14)

find_library(log-lib log)
find_library(android-lib android)

if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(LIBPCAP_INCLUDE_DIR "C:/libpcap-android/output/arm64-v8a/include")
    set(LIBPCAP_LIB_PATH "C:/libpcap-android/output/arm64-v8a/lib/libpcap.a")
else()
    message(FATAL_ERROR "Only arm64-v8a supported. Current ABI: ${ANDROID_ABI}")
endif()

if(EXISTS ${LIBPCAP_LIB_PATH})
    message(STATUS "Found static libpcap at: ${LIBPCAP_LIB_PATH}")
    set(LIBPCAP_AVAILABLE TRUE)
else()
    message(FATAL_ERROR "libpcap not found at: ${LIBPCAP_LIB_PATH}")
    set(LIBPCAP_AVAILABLE FALSE)
endif()

if(LIBPCAP_AVAILABLE)
    include_directories(${LIBPCAP_INCLUDE_DIR})
    add_definitions(-DHAVE_LIBPCAP=1)
endif()

add_library(packet_analyzer SHARED
    native-lib.cpp
    packet_parser.cpp
    session_manager.cpp
    socket_forwarder.cpp
)

if(LIBPCAP_AVAILABLE)
    target_link_libraries(packet_analyzer
        ${LIBPCAP_LIB_PATH}
        ${log-lib}
        ${android-lib}
        m
    )
else()
    target_link_libraries(packet_analyzer
        ${log-lib}
        ${android-lib}
    )
endif()
