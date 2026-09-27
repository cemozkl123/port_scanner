#ifndef NET_UTILS_HPP
#define NET_UTILS_HPP

#include <string>
#include <cstdint>

namespace scanner {

/**
 * @brief Converts an IPv4 dotted-decimal string or hostname into a 32-bit binary IP address in network byte order.
 *
 * @param ip_or_host IPv4 string (e.g. "192.168.1.1") or hostname (e.g. "localhost")
 * @param out_ip Reference to store the resulting 32-bit network-order IP
 * @return true if resolution/conversion succeeded, false otherwise
 */
bool string_to_ip(const std::string& ip_or_host, uint32_t& out_ip);

/**
 * @brief Converts a 32-bit binary IP address in network byte order into a human-readable dotted-decimal string.
 *
 * @param ip 32-bit IP address in network byte order
 * @return std::string representation (e.g. "192.168.1.1")
 */
std::string ip_to_string(uint32_t ip);

/**
 * @brief Determines the local outbound interface IP address for communicating with a target IP.
 *
 * Uses an unconnected UDP routing lookup via getsockname without transmitting any network packets.
 *
 * @param target_ip Target IPv4 address string (e.g. "8.8.8.8")
 * @param out_local_ip Reference to store human-readable local IP string
 * @param out_local_ip_bin Reference to store 32-bit network-order local IP
 * @return true if the outbound interface was successfully resolved, false otherwise
 */
bool get_local_ip(const std::string& target_ip, std::string& out_local_ip, uint32_t& out_local_ip_bin);

} // namespace scanner

#endif // NET_UTILS_HPP
