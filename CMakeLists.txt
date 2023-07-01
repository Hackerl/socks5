cmake_minimum_required(VERSION 3.17)
project(socks5)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(aio CONFIG REQUIRED)

add_executable(socks5 main.cpp)
target_link_libraries(socks5 PRIVATE aio::aio)