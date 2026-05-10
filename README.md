# 📡 TracketPacket
**The Ultra-Lightweight, Private Network Intelligence Suite for Raspberry Pi.**

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Hardware: Raspberry Pi](https://img.shields.io/badge/Hardware-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)

TracketPacket is a "Zero-Dependency" network monitoring tool designed to give you **Fing-level intelligence** without the cloud, without the subscriptions, and without the bloat. It's built specifically for the Raspberry Pi but runs on any Linux or Windows machine.

---

## ✨ Why TracketPacket?

Most network scanners are either too simple (missing history) or too complex (requiring Docker, DBs, and heavy agents). **TracketPacket** hits the sweet spot:

*   **🔒 100% Private**: Your network data never leaves your LAN. No accounts, no cloud, no "telemetry."
*   **🚀 Zero-Dependency**: Runs on a standard Python 3 install. No heavy database engines needed—it uses a high-performance JSON persistence layer.
*   **🛠️ Standalone Binary**: Includes an installer that compiles the app into a single executable for the Raspberry Pi.
*   **⚡ Pro Features**: Integrated Port Scanning, Security Auditing, ISP Intelligence, and Device History.

---

## 📸 Dashboard Preview

> [!TIP]
> The dashboard is a modern, responsive single-page application that feels like a premium desktop app.

*Imagine a screenshot here showing the sleek Blacklist-styled dark mode dashboard.*

---

## 🛠️ Key Features

### 🛡️ Security Audit
Automatically scans common ports (`SSH`, `Telnet`, `FTP`, `SMB`) and assigns a **Security Score** to every device. It provides actionable advice to harden your network.

### 📝 Digital Fence & History
Know exactly when a new device joins your network for the first time. Track "Last Seen" timestamps and keep persistent **Nicknames** and **Notes** for every machine, phone, and IoT lightbulb.

### 🔌 Wake-on-LAN (WOL)
Directly wake up your sleeping PCs or servers from the web interface.

### 📊 Intelligence Engine
*   **OUI Lookup**: Accurate manufacturer detection from a 40k+ entry database.
*   **Categorization**: Smart logic to distinguish between Routers, TVs, Servers, and Phones.
*   **ISP Context**: Real-time public IP and ISP intelligence.

---

## 🚀 One-Step Installation (Raspberry Pi)

We've provided a professional-grade installer that handles everything from system dependencies to `systemd` service configuration.

```bash
# Clone the repository
git clone https://github.com/YourUsername/tracketpacket.git
cd tracketpacket

# Run the Pi Installer
sudo bash scripts/install/install_pi.sh
```

**After installation, access your dashboard at:**
`http://<your-pi-ip>:9001`

---

## 💻 Manual Setup (Linux/Windows)

If you just want to run it without the service:

```bash
# Install system-level dependencies (optional but recommended)
# Ubuntu/Debian: sudo apt install nmap avahi-utils

python server.py
```

---

## 📂 Project Structure

```text
tracketpacket/
├── server.py           # Core Intelligence Engine & HTTP Server
├── index.html          # Professional Single-Page UI
├── oui.tsv             # Manufacturer Database (40k+ entries)
├── devices.json        # Persistent Storage (Generated)
└── scripts/
    └── install/
        └── install_pi.sh  # Automated Pi Installer
```

---

## 📜 License
Distributed under the **MIT License**. Built with ☕ and curiosity by **Blacklist Tech**.

---

> "Privacy isn't an option; it's a default." 📡
