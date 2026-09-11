//Trial Code to check if files build correctly
#include <iostream>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  Custom C++ TCP/UDP Port Scanner Setup " << std::endl;
    std::cout << "========================================" << std::endl;

    // Check concurrency capability
    unsigned int hardware_threads = std::thread::hardware_concurrency();
    std::cout << "[+] Hardware concurrency cores available: " << hardware_threads << std::endl;

    std::cout << "[+] Environment and headers verified successfully." << std::endl;
    return 0;
}
