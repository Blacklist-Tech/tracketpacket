# TracketPacket

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)]()

A lightweight, privacy-first network intelligence tool for monitoring devices on your local network. Runs on a Raspberry Pi with zero cloud dependencies.

## Features

- **Device Discovery** — Scans your LAN and identifies every connected device with manufacturer lookup via OUI database
- **Security Audit** — Checks common ports (SSH, Telnet, FTP, SMB) and assigns a security score with actionable hardening advice
- **Change Detection** — Tracks first-seen and last-seen timestamps. Know when new devices join your network
- **Wake-on-LAN** — Wake sleeping machines directly from the web dashboard
- **Persistent Notes** — Assign nicknames and notes to devices, persisted across reboots
- **ISP Intelligence** — Displays your public IP and ISP information
- **Zero Cloud** — All data stays on your device. No accounts, no telemetry, no external services

## Quick Start

### Prerequisites
- Python 3.8 or later
- `nmap` (optional, for enhanced port scanning)

### Installation

```bash
git clone https://github.com/Blacklist-Tech/tracketpacket.git
cd tracketpacket
python server.py
```

Open `http://localhost:9001` in your browser.

### Raspberry Pi Deployment

```bash
git clone https://github.com/Blacklist-Tech/tracketpacket.git
cd tracketpacket
sudo bash scripts/install/install_pi.sh
```

The installer configures a `systemd` service so TracketPacket starts on boot and runs on port 9001.

## Project Structure

```
tracketpacket/
├── server.py              # HTTP server and scan engine
├── index.html             # Web dashboard
├── oui.tsv                # IEEE OUI manufacturer database
└── scripts/
    └── install/
        └── install_pi.sh  # Raspberry Pi installer
```

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.

## License

MIT © [Blacklist Tech](https://github.com/Blacklist-Tech)
