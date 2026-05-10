#!/bin/bash

# TracketPacket Pro Binary Installer for Raspberry Pi
# (c) 2026 Blacklist Tech

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📡 TracketPacket Pro Binary Installer${NC}"
echo -e "${BLUE}====================================${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (use sudo)${NC}"
  exit 1
fi

# 1. Install Dependencies
echo -e "${GREEN}[1/5] Installing system dependencies...${NC}"
apt-get update
apt-get install -y nmap avahi-utils python3-pip python3-venv binutils

# 2. Prepare Build Environment
echo -e "${GREEN}[2/5] Preparing build environment...${NC}"
TEMP_DIR=$(mktemp -d)
cp -r . "$TEMP_DIR"
cd "$TEMP_DIR"

# 3. Install PyInstaller
echo -e "${GREEN}[3/5] Installing PyInstaller...${NC}"
python3 -m pip install --upgrade pip
python3 -m pip install pyinstaller

# 4. Build Binary
echo -e "${GREEN}[4/5] Compiling TracketPacket into a standalone binary...${NC}"
# Note: We bundle index.html and oui.tsv into the binary
# We keep devices.json external for persistence
/home/$(logname)/.local/bin/pyinstaller --onefile \
    --name tracketpacket \
    --add-data "index.html:." \
    --add-data "oui.tsv:." \
    server.py

# 5. Install Binary and Service
echo -e "${GREEN}[5/5] Finalizing installation...${NC}"
cp dist/tracketpacket /usr/local/bin/
chmod +x /usr/local/bin/tracketpacket

# Create Data Directory
mkdir -p /var/lib/tracketpacket
chmod 777 /var/lib/tracketpacket

# Create Systemd Service
cat <<EOF > /etc/systemd/system/tracketpacket.service
[Unit]
Description=TracketPacket Network Intelligence
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tracketpacket --port 9001 --data /var/lib/tracketpacket/devices.json
WorkingDirectory=/var/lib/tracketpacket
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tracketpacket
systemctl start tracketpacket

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo -e "TracketPacket is now running at: ${BLUE}http://$(hostname -I | awk '{print $1}'):9001${NC}"
echo -e "Binary location: ${BLUE}/usr/local/bin/tracketpacket${NC}"
echo -e "Data location:   ${BLUE}/var/lib/tracketpacket/devices.json${NC}"
echo -e "Logs:            ${BLUE}journalctl -u tracketpacket -f${NC}"
echo -e "${GREEN}====================================${NC}"

# Cleanup
rm -rf "$TEMP_DIR"
