cmake_minimum_required(VERSION 3.10)

project(zdtun_vpn)

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

# JNI wrapper
set(JNI_SOURCES
    ${CMAKE_SOURCE_DIR}/src/main/jni/zdtun_vpn.c
)

# Create shared library
add_library(
    zdtun_vpn
    SHARED
    ${ZDTUN_SOURCES}
    ${JNI_SOURCES}
)

# Link against android log library
target_link_libraries(
    zdtun_vpn
    log
)
