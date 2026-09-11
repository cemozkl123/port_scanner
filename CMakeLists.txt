cmake_minimum_required(VERSION 3.14)
project(port_scanner VERSION 1.0 LANGUAGES CXX)

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
