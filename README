# Network Sniffer - IDS (Intrusion Detection System)

A low-level network packet sniffer written in Python that captures and analyzes traffic in real time, detecting common network attacks and anomalies.

---

## What it does

The sniffer captures raw packets at the Ethernet level using raw sockets, parses them by protocol, and tracks all active devices on the network. When suspicious behavior is detected, it logs an alert.

Currently it detects the following:

**ARP flood** - identifies devices sending ARP requests at an abnormally high rate, which may indicate network scanning or a precursor to ARP spoofing.

**ARP/IP spoofing** - detects when a device's MAC address changes between packets, which suggests someone is impersonating another device on the network.

**ICMP flood** - counts ICMP echo requests (pings) per device over a rolling interval and alerts when the rate exceeds the configured threshold.

**Bandwidth abuse** - tracks total bytes sent per device and alerts when a device exceeds the configured bandwidth limit within the check interval.

---

## Project structure

```
sniffer.py       # Main file. Packet capture loop, detection logic, HTTP server
```

---

## How to run

Requires root privileges to open raw sockets.

```bash
sudo python3 sniffer.py
```

Once running, the HTTP API is available at:

```
http://localhost:8000/devices
http://localhost:8000/alerts
```

---

## Configuration

All thresholds are defined at the top of `sniffer.py`:

| Parameter | Default | Description |
|---|---|---|
| ARP_REQUEST_THRESHOLD | 50 | Max ARP requests per minute before alert |
| ICMP_THRESHOLD | 50 | Max ICMP pings per check interval before alert |
| ICMP_CHECK_INTERVAL | 10 | Seconds between ICMP checks |
| BANDWIDTH_THRESHOLD | 10 MB | Max bytes per device per interval |
| BANDWIDTH_INTERVAL | 30 | Seconds between bandwidth checks |
| TTL | 300 | Seconds before an inactive device is removed |
| CLEAN_INTERVAL | 60 | Seconds between inactive device cleanup runs |

---

## HTTP API

A lightweight HTTP server runs in a background thread and exposes the internal state of the sniffer.

**GET /devices** - returns all currently tracked devices and their counters.

**GET /alerts** - returns the full history of alerts generated since the sniffer started.

---

## Requirements

- Python 3.x
- Linux (uses `AF_PACKET` raw sockets, not available on Windows or macOS)
- Root or `CAP_NET_RAW` capability

---

## Work in progress

The following features are planned or partially implemented:

- SYN flood detection (TCP tracker is in place, detection logic pending)
- HTTP server handler class (currently incomplete)
- Status endpoint (`/status`) with uptime and global counters
- Sliding window counters for more accurate rate detection (current implementation uses time since first seen, which dilutes rates over time)
- Configurable alert output (file, webhook, syslog)