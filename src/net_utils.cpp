#include "net_utils.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

namespace scanner {

bool string_to_ip(const std::string& ip_or_host, uint32_t& out_ip) {
    if (ip_or_host.empty()) {
        return false;
    }

    struct in_addr addr{};
    // First attempt: dotted-decimal format (e.g., "192.168.1.1")
    if (inet_pton(AF_INET, ip_or_host.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }

    // Second attempt: DNS / hostname resolution (e.g., "localhost")
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int status = getaddrinfo(ip_or_host.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        return false;
    }

    auto* ipv4 = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    out_ip = ipv4->sin_addr.s_addr;

    freeaddrinfo(res);
    return true;
}

std::string ip_to_string(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr{};
    addr.s_addr = ip;
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != nullptr) {
        return std::string(buf);
    }
    return "";
}

bool get_local_ip(const std::string& target_ip, std::string& out_local_ip, uint32_t& out_local_ip_bin) {
    uint32_t target_bin = 0;
    if (!string_to_ip(target_ip, target_bin)) {
        return false;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false;
    }

    struct sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = target_bin;
    target_addr.sin_port = htons(53); // Arbitrary destination port

    // Connect on a UDP socket assigns local address according to routing tables without sending data
    if (connect(sock, reinterpret_cast<const struct sockaddr*>(&target_addr), sizeof(target_addr)) < 0) {
        close(sock);
        return false;
    }

    struct sockaddr_in local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, reinterpret_cast<struct sockaddr*>(&local_addr), &addr_len) < 0) {
        close(sock);
        return false;
    }

    close(sock);

    out_local_ip_bin = local_addr.sin_addr.s_addr;
    out_local_ip = ip_to_string(out_local_ip_bin);

    return !out_local_ip.empty();
}

} // namespace scanner
