#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <cstring>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "checksum.hpp"
#include "net_utils.hpp"

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  Custom C++ TCP/UDP Port Scanner Setup " << std::endl;
    std::cout << "========================================" << std::endl;

    // Check concurrency capability
    unsigned int hardware_threads = std::thread::hardware_concurrency();
    std::cout << "[+] Hardware concurrency cores available: " << hardware_threads << std::endl;

    // 1. Verify Network Utilities
    std::cout << "\n[*] Testing Network Utilities..." << std::endl;
    std::string test_ip = "192.168.1.1";
    uint32_t parsed_ip = 0;
    if (scanner::string_to_ip(test_ip, parsed_ip)) {
        std::cout << "  [+] string_to_ip: " << test_ip << " -> 0x" 
                  << std::hex << ntohl(parsed_ip) << std::dec << std::endl;
        std::cout << "  [+] ip_to_string: " << scanner::ip_to_string(parsed_ip) << std::endl;
    }

    std::string local_ip;
    uint32_t local_ip_bin = 0;
    if (scanner::get_local_ip("8.8.8.8", local_ip, local_ip_bin)) {
        std::cout << "  [+] Outbound local interface IP resolved: " << local_ip << std::endl;
    } else {
        std::cout << "  [-] Notice: No default route to 8.8.8.8 (offline/isolated network)" << std::endl;
    }

    // 2. Verify RFC 1071 Checksum Algorithm
    std::cout << "\n[*] Testing RFC 1071 Checksum Algorithm..." << std::endl;
    const uint8_t sample_data[] = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    uint16_t csum = scanner::calculate_checksum(sample_data, sizeof(sample_data));
    std::cout << "  [+] Calculated 16-bit Checksum: 0x" 
              << std::hex << std::setw(4) << std::setfill('0') << ntohs(csum) 
              << std::dec << std::endl;

    // Self-verification: appending checksum and recomputing should equal 0x0000 or 0xffff
    std::vector<uint8_t> verify_buf(std::begin(sample_data), std::end(sample_data));
    verify_buf.resize(verify_buf.size() + sizeof(csum));
    std::memcpy(verify_buf.data() + sizeof(sample_data), &csum, sizeof(csum));
    uint16_t verify_result = scanner::calculate_checksum(verify_buf.data(), verify_buf.size());
    std::cout << "  [+] Checksum self-verification: " 
              << ((verify_result == 0x0000 || verify_result == 0xffff) ? "PASSED" : "FAILED") 
              << std::endl;

    // 3. Verify TCP Pseudo-Header Checksum
    std::cout << "\n[*] Testing TCP Pseudo-Header Checksum..." << std::endl;
    struct tcphdr tcp{};
    tcp.source = htons(49152);
    tcp.dest = htons(80);
    tcp.seq = htonl(1000);
    tcp.ack_seq = 0;
    tcp.doff = 5;
    tcp.syn = 1;
    tcp.window = htons(65535);
    tcp.check = 0;
    tcp.urg_ptr = 0;

    uint32_t src_ip_bin = 0;
    uint32_t dst_ip_bin = 0;
    scanner::string_to_ip("192.168.1.50", src_ip_bin);
    scanner::string_to_ip("192.168.1.1", dst_ip_bin);

    uint16_t tcp_csum = scanner::calculate_tcp_checksum(src_ip_bin, dst_ip_bin, &tcp, nullptr, 0);
    std::cout << "  [+] Crafted TCP SYN Checksum: 0x" 
              << std::hex << std::setw(4) << std::setfill('0') << ntohs(tcp_csum) 
              << std::dec << std::endl;

    std::cout << "\n[+] Phase 2: Checksum & Network Utilities initialized successfully." << std::endl;
    return 0;
}
