cmake_minimum_required(VERSION 3.17)
project(socks5)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

if (WIN32 AND STATIC_BUILD)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()

find_package(aio CONFIG REQUIRED)

add_executable(socks5 main.cpp)
target_link_libraries(socks5 PRIVATE aio::aio $<$<AND:$<PLATFORM_ID:Linux>,$<BOOL:${STATIC_BUILD}>>:-static-pie>)