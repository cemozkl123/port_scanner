#include "checksum.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <vector>

namespace scanner {

uint16_t calculate_checksum(const void* data, size_t length) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    // Accumulate 16-bit words
    while (length > 1) {
        uint16_t word = 0;
        std::memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += sizeof(uint16_t);
        length -= sizeof(uint16_t);
    }

    // Handle trailing odd byte by padding with zero
    if (length == 1) {
        uint16_t word = 0;
        uint8_t odd_byte = *ptr;
        std::memcpy(&word, &odd_byte, 1);
        sum += word;
    }

    // Fold 32-bit sum into 16 bits (add carries)
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return bitwise one's complement
    return static_cast<uint16_t>(~sum);
}

uint16_t calculate_tcp_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    const struct tcphdr* tcp_header,
    const void* payload,
    size_t payload_len
) {
    size_t tcp_header_len = sizeof(struct tcphdr);
    size_t tcp_segment_len = tcp_header_len + payload_len;

    // 1. Construct the TCP pseudo-header
    TcpPseudoHeader pseudo_header{};
    pseudo_header.src_ip = src_ip;
    pseudo_header.dst_ip = dst_ip;
    pseudo_header.reserved = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(static_cast<uint16_t>(tcp_segment_len));

    // 2. Allocate contiguous buffer: pseudo-header + TCP header + payload
    size_t total_buf_len = sizeof(TcpPseudoHeader) + tcp_segment_len;
    std::vector<uint8_t> buffer(total_buf_len, 0);

    // Copy Pseudo Header
    std::memcpy(buffer.data(), &pseudo_header, sizeof(TcpPseudoHeader));

    // Copy TCP Header with checksum field zeroed
    struct tcphdr temp_tcphdr = *tcp_header;
    temp_tcphdr.check = 0;
    std::memcpy(buffer.data() + sizeof(TcpPseudoHeader), &temp_tcphdr, tcp_header_len);

    // Copy Payload (if present)
    if (payload != nullptr && payload_len > 0) {
        std::memcpy(buffer.data() + sizeof(TcpPseudoHeader) + tcp_header_len, payload, payload_len);
    }

    // 3. Compute checksum over the combined buffer
    return calculate_checksum(buffer.data(), total_buf_len);
}

} // namespace scanner
