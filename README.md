# ft_nmap - Network Port Scanner

A multithreaded network port scanner written in C, inspired by the iconic [Nmap](https://nmap.org/) tool. This project reimplements core Nmap functionality from scratch using raw sockets and the `libpcap` library, as part of the [42 school](https://42.fr/) cybersecurity curriculum.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
  - [Architecture](#architecture)
  - [Scan Techniques](#scan-techniques)
  - [Packet Lifecycle](#packet-lifecycle)
  - [Multithreading Model](#multithreading-model)
- [Build](#build)
- [Usage](#usage)
- [Options](#options)
- [Output](#output)
- [Technical Challenges](#technical-challenges)
- [Dependencies](#dependencies)

## Overview

`ft_nmap` is a low-level network scanner that crafts raw IP/TCP/UDP packets to probe remote hosts and determine the state of their ports. Unlike tools that rely on the OS networking stack (e.g. `connect()` scans), this implementation manually constructs every layer of the packet -- IP headers, TCP/UDP headers, checksums -- giving full control over the scan behavior.

The scanner supports **6 distinct scan types**, **multithreaded execution** with up to 250 threads, and can target single hosts, multiple hosts from a file, or randomly generated IP addresses.

## Features

- **6 scan types**: SYN, NULL, ACK, FIN, XMAS, UDP
- **Raw socket packet crafting**: IP and TCP/UDP headers built manually with proper checksums
- **Packet capture with libpcap**: Responses captured and filtered using BPF (Berkeley Packet Filter) expressions
- **Host discovery**: ICMP Echo (ping) to verify host availability before scanning
- **DNS resolution**: Accepts both IPv4 addresses and hostnames
- **Multithreading**: Configurable thread pool (up to 250 threads) with mutex/condition-variable synchronization
- **Service detection**: Maps open ports to known service names (SSH, HTTP, FTP, DNS, etc.)
- **Multiple target sources**: Single IP/hostname, file with host list, or random target generation
- **Configurable options**: TTL, retries, port range, network interface selection, ping toggle

## How It Works

### Architecture

```
main()
  |
  +-- Argument parsing (handle_arg)
  |     +-- Parse scan types, ports, threads, options
  |     +-- Load hostnames from CLI, file, or random generation
  |
  +-- For each hostname:
  |     +-- DNS resolution (getaddrinfo / inet_pton)
  |     +-- ICMP ping (optional host discovery)
  |     +-- Build host linked list
  |
  +-- Scan execution
  |     +-- Single-threaded mode (--speedup 0 or omitted)
  |     |     +-- Sequential scan of all ports x all scan types
  |     +-- Multithreaded mode (--speedup N)
  |           +-- Thread pool initialization (raw sockets + pcap handles)
  |           +-- Main thread dispatches work via condition variables
  |           +-- Worker threads craft, send, and capture packets
  |
  +-- Result display
        +-- Per-host port states, services, scan summary
```

### Scan Techniques

Each scan type sends a specifically crafted TCP or UDP packet and interprets the response (or lack thereof) to determine port state:

| Scan Type | Packet Flags | Open | Closed | Filtered |
|-----------|-------------|------|--------|----------|
| **SYN** | SYN | SYN+ACK received | RST received | No response / ICMP unreachable |
| **NULL** | (none) | No response | RST received | ICMP unreachable |
| **ACK** | ACK | N/A (unfiltered if RST) | RST received | No response / ICMP unreachable |
| **FIN** | FIN | No response | RST received | ICMP unreachable |
| **XMAS** | FIN+PSH+URG | No response | RST received | ICMP unreachable |
| **UDP** | (UDP packet) | UDP response | ICMP port unreachable | ICMP other unreachable |

Port states follow the Nmap convention:
- **open**: The port is accepting connections
- **closed**: The port is reachable but no service is listening
- **filtered**: A firewall is blocking probe packets
- **unfiltered**: The port is reachable (ACK scan only), but open/closed cannot be determined
- **open/filtered**: No response received -- could be open or filtered (NULL, FIN, XMAS, UDP scans)

### Packet Lifecycle

1. **Craft**: Raw IP header + TCP/UDP header are built in a `char[4096]` buffer. Checksums are computed using a pseudo-header (source IP, dest IP, protocol, segment length) per RFC 793.
2. **Filter**: A BPF filter is compiled and applied to the pcap handle: `src host <target> and (tcp|icmp) and src port <target_port> and dst port <src_port>`.
3. **Send**: The packet is sent via `sendto()` on a `SOCK_RAW` / `IPPROTO_RAW` socket.
4. **Receive**: `poll()` waits for a response on the pcap file descriptor. `pcap_next_ex()` reads the captured packet.
5. **Analyze**: The response IP header is inspected to determine if it's TCP or ICMP. TCP flags (SYN, ACK, RST) and ICMP type/code dictate the port state.
6. **Retry**: If no response is received within the timeout, the packet is retransmitted (configurable via `--max-retries`).

### Multithreading Model

The threading model uses a **thread pool with condition variables**:

- The **main thread** acts as a dispatcher. It iterates over hosts, ports, and scan types, and assigns work to idle threads.
- Each **worker thread** owns its own:
  - Raw socket (`SOCK_RAW`)
  - pcap handle (avoids data races on packet capture)
  - Mutex + condition variable pair
- The main thread locks a worker's mutex, sets the target (host, port, scan type), signals the condition variable, and unlocks.
- The worker wakes up, performs the scan, and waits for the next assignment.
- A global `g_done` flag (protected by `g_lock`) signals all threads to terminate gracefully.

This design avoids shared-state contention on the hot path (each thread has its own socket and pcap handle) while still allowing coordinated work distribution.

## Build

```bash
# Requires gcc, make, and libpcap-dev
sudo apt install libpcap-dev    # Debian/Ubuntu

make
```

The binary `ft_nmap` will be created in the project root.

> **Note**: Raw sockets require root privileges. Run with `sudo`.

## Usage

```bash
sudo ./ft_nmap --ip <target> [options]
```

### Examples

```bash
# Basic SYN scan on default ports (1-1024)
sudo ./ft_nmap --ip scanme.nmap.org --scan SYN

# Full scan with 100 threads on ports 20-80
sudo ./ft_nmap --ip 192.168.1.1 --scan SYN NULL ACK FIN XMAS UDP --speedup 100 --ports 20/80

# Scan multiple hosts from file
sudo ./ft_nmap --file targets.txt --scan SYN ACK --speedup 50

# Scan random targets without ping
sudo ./ft_nmap --rand-target 10 --scan SYN --no-ping --speedup 20

# Specify network interface and TTL
sudo ./ft_nmap --ip 10.0.0.1 --scan SYN --interface eth0 --ttl 128
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ip <host>` | Target hostname or IPv4 address (required unless `--file` or `--rand-target` is used) | - |
| `--file <path>` | File containing one hostname/IP per line | - |
| `--scan <types...>` | Space-separated scan types: `SYN`, `NULL`, `ACK`, `FIN`, `XMAS`, `UDP`, `ALL` | ALL |
| `--ports <X/Y>` | Port range to scan (max 1024 ports). Single port: `--ports 80` | 1/1024 |
| `--speedup <N>` | Number of threads (1-250). 0 = single-threaded | 0 |
| `--no-ping` | Skip ICMP ping before scanning | ping enabled |
| `--max-retries <N>` | Max retransmissions per probe (1-250) | 2 |
| `--ttl <N>` | IP Time-To-Live value (0-255) | 64 |
| `--interface <name>` | Network interface to use (e.g. `eth0`, `wlan0`) | any |
| `--verbose` | Print per-port scan progress | disabled |
| `--rand-target <N>` | Generate N random IPv4 addresses as targets | - |
| `--help` | Display usage information | - |

## Output

```
Scan Configurations:
Nbr of Ports to scan: 1024
Nbr of threads: 50
Scans to be performed: SYN NULL FIN XMAS ACK UDP

HOST: scanme.nmap.org
Host is up
Not shown: 1020 ports
PORT      STATE              SERVICE
22/tcp    open(SYN)          ssh
80/tcp    open(SYN)          http
443/tcp   open(SYN)          https
9929/tcp  open(SYN)          nping-echo

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

## Technical Challenges

- **Raw packet construction**: Every field of the IP and TCP/UDP headers must be set correctly -- wrong checksums, byte ordering (htons/htonl), or header lengths result in silently dropped packets.
- **Thread-safe packet capture**: Each thread needs its own `pcap_t` handle. Sharing a single handle across threads causes data races and missed packets. BPF filters must be set per-handle to isolate each thread's traffic.
- **Reliable response matching**: Source port randomization + BPF filters ensure each thread only captures responses to its own probes, preventing cross-contamination between concurrent scans.
- **Timeout handling**: The scanner must distinguish between "no response" (filtered/open) and "response not yet arrived". This is handled through `poll()` with configurable timeouts and retry logic.
- **Thread synchronization**: The condition-variable-based dispatch model avoids busy-waiting while maintaining low latency for work assignment.

## Dependencies

| Library | Purpose |
|---------|---------|
| **libpcap** | Packet capture and BPF filtering |
| **pthreads** | Multithreading (POSIX threads) |
| **Standard C libraries** | Socket API, DNS resolution, ICMP |

## License

This project was developed as part of the 42 school curriculum.
