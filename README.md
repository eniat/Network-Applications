# Network Applications

Python networking toolkit implementing ping, traceroute, a multi-threaded traceroute, a basic web server and a simple HTTP proxy using low-level sockets.

The project demonstrates packet construction, ICMP parsing, UDP/TCP socket programming, timeout handling, threading and basic HTTP request/response handling.

## Features

- ICMP ping client.
- UDP and ICMP traceroute.
- Multi-threaded traceroute.
- Basic multi-threaded HTTP web server.
- Simple HTTP proxy with file-based caching.
- Manual ICMP checksum calculation.
- RTT, TTL and packet loss reporting.
- Command-line interface using `argparse`.
- No third-party dependencies.

## Tech Stack

- Python 3
- Raw sockets
- TCP and UDP sockets
- ICMP packet parsing
- Threading
- HTTP handling
- File-based caching

## Repository Structure

```text
.
├── NetworkApplications.py
└── README.md
```

## Requirements

The project only uses the Python standard library.

Raw ICMP sockets normally require administrator/root privileges; use `sudo` for ICMP ping and traceroute commands on Linux/macOS.

## Commands

```text
ping          Run ICMP ping
traceroute    Run UDP or ICMP traceroute
mtroute       Run multi-threaded traceroute
web           Run a basic HTTP web server
proxy         Run a basic HTTP proxy
```

Show command help:

```bash
python3 NetworkApplications.py
```

## ICMP Ping

```bash
sudo python3 NetworkApplications.py ping lancaster.ac.uk
sudo python3 NetworkApplications.py ping lancaster.ac.uk --count 5
sudo python3 NetworkApplications.py ping lancaster.ac.uk --timeout 3
```

The ping implementation resolves the hostname, builds ICMP echo requests, sends raw packets, parses replies and prints RTT, packet loss and summary statistics.

## Traceroute

```bash
sudo python3 NetworkApplications.py traceroute lancaster.ac.uk --protocol udp
sudo python3 NetworkApplications.py traceroute lancaster.ac.uk --protocol icmp
```

The traceroute implementation increases TTL values, sends three probes per hop and listens for ICMP Time Exceeded or destination responses.

The output shows hop addresses, optional hostnames and RTT values.

## Multi-threaded Traceroute

```bash
sudo python3 NetworkApplications.py mtroute lancaster.ac.uk --protocol udp
sudo python3 NetworkApplications.py mtroute lancaster.ac.uk --protocol icmp
```

This version separates probe sending and response collection into different threads.

Shared data structures for sent times, hop addresses and RTTs are protected with a lock.

## Web Server

```bash
python3 NetworkApplications.py web --port 8080
```

Then open:

```text
http://127.0.0.1:8080/index.html
```

The requested file must exist in the same directory as the script.

The server accepts TCP connections, creates a thread per request, reads the requested file and returns a basic HTTP response.

Missing files return a simple `404 Not Found` response.

## HTTP Proxy

```bash
python3 NetworkApplications.py proxy --port 8000
```

The proxy accepts HTTP requests, extracts the URL, checks the local `cache/` directory and either serves a cached response or fetches the content from the remote server.

Repeated requests to the same URL can be returned from cache.

## Example Workflow

```bash
sudo python3 NetworkApplications.py ping lancaster.ac.uk --count 3
sudo python3 NetworkApplications.py traceroute lancaster.ac.uk --protocol udp
sudo python3 NetworkApplications.py mtroute lancaster.ac.uk --protocol icmp
python3 NetworkApplications.py web --port 8080
python3 NetworkApplications.py proxy --port 8000
```

## What This Demonstrates

This project shows how common network tools work internally instead of relying on existing utilities.

It covers packet-level implementation, routing-path discovery, raw socket handling, concurrent request handling and simple proxy caching.

## Limitations

- ICMP commands may require root/admin privileges.
- IPv6 is not implemented.
- The web server is intentionally minimal.
- The proxy supports simple HTTP traffic, not HTTPS.
- Cache invalidation and advanced HTTP headers are not handled.

## File Summary

`NetworkApplications.py` contains all application logic.

The script defines a shared `NetworkApplication` base class and implements `ICMPPing`, `Traceroute`, `MultiThreadedTraceRoute`, `WebServer` and `Proxy`.

Each tool is launched from the command line using its matching subcommand.

## Security and Usage Notes

This project is intended for local educational use only.

The web server and proxy are intentionally minimal and are not hardened for public internet deployment. They should not be exposed directly to the internet.

Only run the ping, traceroute and proxy tools against hosts, systems or networks you own or have permission to test.

## Usage Notice

This repository is provided for portfolio and review purposes only.

All rights are reserved. No permission is granted to copy, redistribute, submit, or reuse this work, in whole or in part, for academic coursework, assessment, or commercial purposes.

Where this repository relates to university coursework, it is shared only to demonstrate my own technical work and should not be used by other students as a submission or solution.
