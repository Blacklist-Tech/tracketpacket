# TracketPacket 📡
**Local Network Device Tracker for Raspberry Pi**

Zero-dependency Python app that scans your LAN and tracks every device — with persistent nicknames.

## Quick Start (Raspberry Pi)

```bash
# SSH into your Pi, clone/copy this folder, then:
cd tracketpacket
python3 server.py
```

Open `http://<pi-ip>:8080` from any device on the network.

## Features
- **Auto-scan** every 60 seconds via ARP / ip neigh / nmap
- **Persistent nicknames** and notes (saved to `devices.json`)
- **Online/Offline** status tracking with first-seen dates
- **Search & filter** by name, IP, MAC, vendor
- **Zero dependencies** — Python 3.7+ stdlib only
- **Mobile-friendly** responsive UI

## Options
```bash
python3 server.py --port 3000    # Custom port
```

## Run on Boot (systemd)
```bash
sudo nano /etc/systemd/system/tracketpacket.service
```
```ini
[Unit]
Description=TracketPacket Network Tracker
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/tracketpacket/server.py
WorkingDirectory=/home/pi/tracketpacket
Restart=always
User=pi

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable tracketpacket
sudo systemctl start tracketpacket
```
