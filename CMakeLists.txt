cmake_minimum_required(VERSION 3.10)
project(CppProxyServer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)

set(SOURCES
  src/main.cpp
  src/http_req.cpp
  src/utils.cpp
)

# Use target_include_directories instead of include_directories
add_executable(server ${SOURCES})

target_include_directories(server PRIVATE include)

message(STATUS "Proxy Server project configured.")