# Custom C++ TCP/UDP Port Scanner ("Sniffer")

A high-performance, low-level network port scanner and packet sniffer written in C++ from scratch. This project demonstrates systems-level network programming, raw socket manipulation, manual packet assembly, and protocol-level traffic analysis.

---

## 🎯 Project Goals

- **Bypass Standard Transport Abstractions:** Directly manipulate Layer 3 (IPv4) and Layer 4 (TCP/UDP) headers using raw sockets (`SOCK_RAW`).
- **Implement Half-Open TCP SYN Scanning:** Send crafted `SYN` packets and analyze responses (`SYN-ACK` vs. `RST`) without completing the full 3-way handshake, minimizing connection overhead and footprint.
- **Deep Protocol Understanding:** Manually calculate IP and TCP checksums (including the TCP pseudo-header), manage network-vs-host byte order, and dissect raw incoming network frames.
- **Concurrent Architecture:** Scale scanning throughput safely across port ranges using modern C++ concurrency (`std::thread`, synchronization primitives).

---

## 🛠️ Technology Stack & Core Headers

| Component | Technology / Library | Description |
| :--- | :--- | :--- |
| **Language** | C++17 / C++20 | Modern features (`<thread>`, `<vector>`, `<chrono>`, `<memory>`, `<mutex>`) |
| **Sockets** | `<sys/socket.h>` | Core socket initialization and options (`socket()`, `setsockopt()`) |
| **IPv4 Structures** | `<netinet/ip.h>` | `struct iphdr` for crafting raw IP datagram headers |
| **TCP Structures** | `<netinet/tcp.h>` | `struct tcphdr` for port assignment, sequence numbers, and flags |
| **Byte Ordering** | `<arpa/inet.h>` | Network-to-host (`ntohs`, `ntohl`) & host-to-network (`htons`, `htonl`) conversions |
| **POSIX Operations** | `<unistd.h>` | Low-level file descriptor management |
| **Build System** | CMake / Make | Cross-platform build management (GCC / Clang) |

---

## 🏛️ System Architecture

```text
+-------------------------------------------------------------------------+
|                              CLI & Controller                           |
|                     (Target parsing, Port range, Threads)               |
+-------------------------------------------------------------------------+
       |                                                               |
       v                                                               v
+----------------------------+                   +----------------------------+
|     Sender Thread(s)       |                   |      Receiver Thread       |
|                            |                   |                            |
| 1. Craft IPv4 Header       |                   | 1. Capture via SOCK_RAW    |
| 2. Craft TCP Header (SYN)  |                   | 2. Strip & inspect IP hdr  |
| 3. Compute Checksums       |                   | 3. Verify TCP Flags        |
| 4. sendto() via SOCK_RAW   |                   |    - SYN-ACK -> Port OPEN  |
+----------------------------+                   |    - RST     -> Port CLOSED|
                                                 | 4. Correlate with target   |
                                                 +----------------------------+
```

### 1. Packet Construction Engine
- **IPv4 Header:** Version (4), Header Length (IHL = 5), TTL (typically 64), Protocol (`IPPROTO_TCP`), Source IP, Destination IP.
- **TCP Header:** Source Port (ephemeral / randomized), Destination Port (target port), Sequence Number, TCP Flags (`SYN = 1`), Window Size, Checksum.
- **Checksum Calculation:** 16-bit one's complement sum across the IP header and the TCP segment + pseudo-header (Source IP, Destination IP, Protocol, TCP Length).

### 2. Socket Configuration
- Raw socket creation: `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` or `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`.
- Socket option: `setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt))` to signal manual IP header inclusion.

### 3. Concurrency Model
- Separate transmitter threads and a dedicated listener thread to avoid missing asynchronous inbound replies.
- Synchronized thread-safe data structures for tracking active scans, timeouts, and open port discoveries.

---

## ⚠️ Platform & Permission Requirements

> [!IMPORTANT]
> **POSIX Environment Required:**
> Raw socket creation with custom headers relies on POSIX networking headers (`<netinet/ip.h>`, `<sys/socket.h>`). On Windows, this project should be built and executed within **WSL2 (Windows Subsystem for Linux)** or a **Linux VM/container**. Windows native sockets (Winsock) have heavily restricted raw socket capabilities since Windows XP SP2/Vista.

> [!WARNING]
> **Elevated Privileges:**
> Creating raw sockets requires superuser permissions. Running the compiled binary requires `sudo` or the `CAP_NET_RAW` Linux capability:
> ```bash
> sudo ./port_scanner <target-ip> <start-port> <end-port>
> # or assign capability without running full sudo:
> sudo setcap cap_net_raw+ep ./port_scanner
> ```

> [!NOTE]
> **Kernel RST Suppression:**
> Because the OS kernel may not be aware of your raw socket's TCP state machine, when the target returns a `SYN-ACK`, the host kernel might automatically reply with an unwanted `RST`. This can be prevented during local testing using `iptables`:
> ```bash
> sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
> ```

---

## 🗺️ Step-by-Step Implementation Roadmap

We will proceed iteratively across the following phases:

- [ ] **Phase 1: Environment & Build System Setup**
  - Verify compiler toolchain (GCC/Clang, CMake, WSL2 environment).
  - Setup directory structure (`src/`, `include/`, `tests/`, `CMakeLists.txt`).

- [ ] **Phase 2: Checksum & Network Utilities**
  - Implement Internet Checksum algorithm (RFC 1071).
  - Implement TCP pseudo-header calculation.
  - IP string to network binary address conversion helpers.

- [ ] **Phase 3: Packet Crafting Engine**
  - IPv4 header builder (`struct iphdr`).
  - TCP header builder (`struct tcphdr`) with configurable flags (SYN, ACK, FIN, RST).
  - Packet buffer assembly & serialization.

- [ ] **Phase 4: Raw Socket Transmitter**
  - Raw socket creation and setting `IP_HDRINCL`.
  - Detecting local source IP and binding/sending to remote destination (`sendto`).

- [ ] **Phase 5: Port Scanner & Response Parser**
  - Dedicated listener socket.
  - Inbound packet parsing: verifying source IP, port, and response TCP flags (`SYN-ACK` = Open, `RST` = Closed).

- [ ] **Phase 6: Multi-threading & Coordination**
  - Concurrency design: worker pool or partitioned port ranges.
  - Thread-safe result accumulator and timeout handling.

- [ ] **Phase 7: CLI Interface & Formatted Output**
  - Command-line argument parsing (target, port ranges, thread count, timeouts).
  - Clean real-time console reporting and summary statistics.

- [ ] **Phase 8: Future Extensions**
  - UDP scanning support (sending UDP datagrams, listening for ICMP Port Unreachable type 3 code 3).
  - Service banner grabbing on open ports.

---

## 📜 Disclaimer
Educational and network diagnostic purposes only. Ensure you have explicit authorization before scanning target networks or devices.
