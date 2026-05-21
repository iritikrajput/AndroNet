cmake_minimum_required(VERSION 3.10)

project(packet_capture_native)

# Set C standard
set(CMAKE_C_STANDARD 11)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src/main/zdtun
    ${CMAKE_SOURCE_DIR}/src/main/jni
)

# zdtun source files
set(ZDTUN_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/zdtun/zdtun.c
    ${CMAKE_SOURCE_DIR}/src/main/zdtun/utils.c
)

# JNI wrappers
set(JNI_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/jni/zdtun_vpn.c
)

set(PCAP_WRITER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/jni/pcap_writer.c
)

# ============================================
# ALWAYS BUILD: VPN mode (works on all devices)
# ============================================
add_library(
    zdtun_vpn
    SHARED
    ${ZDTUN_SOURCES}
    ${JNI_SOURCES}
)

target_link_libraries(
    zdtun_vpn
    log
)

target_link_options(zdtun_vpn PRIVATE "-Wl,-z,max-page-size=16384")

# ============================================
# ALWAYS BUILD: PCAP writer (no libpcap dependency)
# ============================================
add_library(
    pcap_writer
    SHARED
    ${PCAP_WRITER_SOURCES}
)

target_link_libraries(
    pcap_writer
    log
)

target_link_options(pcap_writer PRIVATE "-Wl,-z,max-page-size=16384")

# ============================================
# OPTIONAL: Libpcap capture (only for rooted devices with libpcap)
# This will be skipped on regular Android builds
# For Kali NetHunter: Install libpcap-dev and rebuild
# ============================================
find_library(LIBPCAP_LIB pcap)

if(LIBPCAP_LIB)
    message(STATUS "✅ libpcap found: Building pcap_capture library for rooted mode")

    set(LIBPCAP_JNI_SOURCES
        ${CMAKE_SOURCE_DIR}/src/main/jni/libpcap_capture.c
    )

    add_library(
        pcap_capture
        SHARED
        ${LIBPCAP_JNI_SOURCES}
    )

    target_link_libraries(
        pcap_capture
        ${LIBPCAP_LIB}
        log
    )

    target_link_options(pcap_capture PRIVATE "-Wl,-z,max-page-size=16384")
else()
    message(WARNING "⚠️  libpcap NOT found - Skipping pcap_capture library")
    message(WARNING "    VPN mode will work normally on unrooted devices")
    message(WARNING "    For rooted mode: Install libpcap-dev on Kali NetHunter and rebuild")
endif()
