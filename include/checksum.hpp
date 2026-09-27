#ifndef CHECKSUM_HPP
#define CHECKSUM_HPP

#include <cstdint>
#include <cstddef>
#include <netinet/tcp.h>
#include <netinet/ip.h>

namespace scanner {

/**
 * @brief TCP Pseudo-header used in TCP checksum calculation according to RFC 793.
 */
struct __attribute__((packed)) TcpPseudoHeader {
    uint32_t src_ip;        // Source IP address (in network byte order)
    uint32_t dst_ip;        // Destination IP address (in network byte order)
    uint8_t  reserved{0};   // Reserved byte (must be 0)
    uint8_t  protocol{6};   // Protocol number (IPPROTO_TCP = 6)
    uint16_t tcp_length{0}; // TCP segment length (TCP header + payload) in network byte order
};

/**
 * @brief Computes standard Internet Checksum (RFC 1071) over a contiguous buffer.
 *
 * Sums 16-bit words using one's complement arithmetic, handles trailing odd bytes
 * by zero-padding, folds 32-bit carries, and returns the one's complement.
 *
 * @param data Pointer to buffer
 * @param length Size of buffer in bytes
 * @return 16-bit checksum in network byte order
 */
uint16_t calculate_checksum(const void* data, size_t length);

/**
 * @brief Computes the TCP checksum over the pseudo-header and TCP segment according to RFC 793.
 *
 * @param src_ip Source IP address (network byte order)
 * @param dst_ip Destination IP address (network byte order)
 * @param tcp_header Pointer to TCP header struct (checksum field must be 0)
 * @param payload Pointer to optional payload data (nullptr if none)
 * @param payload_len Length of optional payload in bytes
 * @return 16-bit TCP checksum in network byte order
 */
uint16_t calculate_tcp_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    const struct tcphdr* tcp_header,
    const void* payload = nullptr,
    size_t payload_len = 0
);

} // namespace scanner

#endif // CHECKSUM_HPP
