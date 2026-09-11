cmake_minimum_required(VERSION 3.14)
project(port_scanner VERSION 1.0 LANGUAGES CXX)

# Enforce Linux / POSIX environment
if(WIN32)
    message(FATAL_ERROR "This project requires a Linux / POSIX environment (WSL2, Linux VM, or Docker) due to raw socket (SOCK_RAW) and POSIX network header dependencies (<netinet/ip.h>, <netinet/tcp.h>). Please run CMake inside WSL or a Linux container.")
endif()

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable standard compiler warnings
add_compile_options(-Wall -Wextra -pedantic -O2)

# Threading support (needed for std::thread / pthread)
find_package(Threads REQUIRED)

# Include directories
include_directories(include)

# Define source files
set(SOURCES
    src/main.cpp
)

# Executable target
add_executable(port_scanner ${SOURCES})

# Link pthread
target_link_libraries(port_scanner PRIVATE Threads::Threads)
