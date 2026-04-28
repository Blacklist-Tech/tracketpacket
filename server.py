#!/usr/bin/env python3
"""
TracketPacket — Network Intelligence Platform
Zero-dependency Python 3 server for Raspberry Pi.

Usage:
    python3 server.py              # Port 8080
    python3 server.py --port 3000  # Custom port
"""

import json, os, re, subprocess, sys, socket, time, threading, csv, io
from datetime import datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# ─── Config ──────────────────────────────────────────────────────────────────
PORT = 8080
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "devices.json")
HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
ALLOWED_INTERVALS = [5, 10, 30, 60, 300]

_config = {"scan_interval": 60}
_isp_cache = {"data": None, "expiry": 0}
_latest_scan = []
_scan_timestamp = None
_lock = threading.Lock()           # protects devices.json reads/writes
_scanning = threading.Lock()       # prevents overlapping scan cycles
_was_online = {}                   # {mac: bool} snapshot from previous scan

# ─── Persistent Storage ─────────────────────────────────────────────────────
def load_data():
    if not os.path.exists(DATA_FILE):
        return {"devices": {}, "scan_history": []}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            data = json.loads(raw)
            # Migrate old event types and clean up vendor spam
            for mac in data.get("devices", {}):
                dev = data["devices"][mac]
                # Event migration
                if "events" in dev:
                    for e in dev["events"]:
                        if e["type"] == "JOIN": e["type"] = "ONLINE"
                        if e["type"] == "LEAVE": e["type"] = "OFFLINE"
                # Vendor cleanup (remove ThinkPad spam)
                if "vendor" in dev and "ThinkPad" in dev["vendor"]:
                    dev["vendor"] = "ThinkPad"
            return data
    except Exception as e:
        print(f"[TP] Corrupt data file ({e}), backing up and resetting.", file=sys.stderr)
        try:
            os.rename(DATA_FILE, DATA_FILE + f".bak_{int(time.time())}")
        except OSError:
            pass
        return {"devices": {}, "scan_history": []}

def save_data(data):
    tmp = DATA_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, DATA_FILE)
    except Exception as e:
        print(f"[TP] Save failed: {e}", file=sys.stderr)

# ─── OUI Vendor Lookup ───────────────────────────────────────────────────────
_OUI = {
 "00:50:56":"VMware","00:0c:29":"VMware","00:1c:42":"Parallels",
 "00:03:ff":"Microsoft","00:0d:3a":"Microsoft","00:15:5d":"Microsoft",
 "00:17:fa":"Microsoft","28:18:78":"Microsoft",
 "3c:22:fb":"Apple","a4:83:e7":"Apple","f0:18:98":"Apple",
 "ac:de:48":"Apple","14:98:77":"Apple","dc:a9:04":"Apple",
 "f8:ff:c2":"Apple","78:7b:8a":"Apple","a8:51:ab":"Apple",
 "bc:d0:74":"Apple","28:6a:ba":"Apple","9c:20:7b":"Apple",
 "40:cb:c0":"Apple","64:b0:a6":"Apple","c8:69:cd":"Apple",
 "88:66:a5":"Apple","5c:f7:e6":"Apple","a4:d1:8c":"Apple",
 "00:1b:63":"Apple","d0:81:7a":"Apple","e0:b5:5f":"Apple",
 "38:f9:d3":"Apple","e4:c3:2a":"Apple","c0:a5:3e":"Apple",
 "b0:34:95":"Apple","8c:85:90":"Apple","cc:08:e0":"Apple",
 "4c:57:ca":"Apple","34:08:bc":"Apple","d8:30:62":"Apple",
 "8c:fe:57":"Apple","84:fc:fe":"Apple",
 "b4:f1:da":"Apple","a0:78:17":"Apple","70:56:81":"Apple",
 "58:55:ca":"Apple","f4:5c:89":"Apple","04:e5:36":"Apple",
 "b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi","e4:5f:01":"Raspberry Pi",
 "d8:3a:dd":"Raspberry Pi","2c:cf:67":"Raspberry Pi",
 "30:b5:c2":"TP-Link","50:c7:bf":"TP-Link","ec:08:6b":"TP-Link",
 "b0:be:76":"TP-Link","60:32:b1":"TP-Link","a8:42:a1":"TP-Link",
 "c0:06:c3":"TP-Link",
 "e4:f0:42":"Google","f4:f5:d8":"Google","54:60:09":"Google",
 "a4:77:33":"Google","30:fd:38":"Google","48:d6:d5":"Google",
 "f8:0f:f9":"Google",
 "fc:65:de":"Samsung","cc:07:ab":"Samsung","78:47:1d":"Samsung",
 "ac:5a:14":"Samsung","8c:f5:a3":"Samsung","00:26:37":"Samsung",
 "5c:3a:45":"Samsung","d0:87:e2":"Samsung","a8:7c:01":"Samsung",
 "30:07:4d":"Samsung","18:3a:2d":"Samsung","94:35:0a":"Samsung",
 "a0:d3:7a":"Intel","3c:f0:11":"Intel","00:1e:64":"Intel",
 "68:05:ca":"Intel","48:51:b7":"Intel","f8:94:c2":"Intel",
 "b4:96:91":"Intel","34:13:e8":"Intel",
 "fc:aa:14":"ASUS","2c:fd:a1":"ASUS","04:d4:c4":"ASUS",
 "1c:87:2c":"ASUS","ac:9e:17":"ASUS","00:0c:6e":"ASUS",
 "00:1f:c6":"ASUS",
 "44:07:0b":"Google Nest","18:d6:c7":"Google Nest","64:16:66":"Google Nest",
 "94:b2:cc":"Amazon","fc:65:de":"Amazon","f0:f0:a4":"Amazon",
 "74:c2:46":"Amazon","40:b4:cd":"Amazon","68:54:fd":"Amazon",
 "a0:02:dc":"Amazon","b0:fc:0d":"Amazon",
 "b8:ae:ed":"Netgear","20:e5:2a":"Netgear","c4:04:15":"Netgear",
 "e0:91:f5":"Netgear","9c:3d:cf":"Netgear","a4:2b:8c":"Netgear",
 "00:1e:58":"D-Link","1c:7e:e5":"D-Link","c8:be:19":"D-Link",
 "b0:c5:54":"D-Link","28:10:7b":"D-Link",
 "e8:48:b8":"Dell","f8:bc:12":"Dell","00:14:22":"Dell",
 "b0:83:fe":"Dell","f4:8e:38":"Dell","a4:ba:db":"Dell",
 "00:21:9b":"Dell","d4:be:d9":"Dell",
 "e8:40:f2":"Pegatron/MSI","00:25:22":"ASRock","d8:cb:8a":"Micro-Star",
 "74:d4:35":"Giga-Byte","94:de:80":"Giga-Byte",
 "c0:3f:d5":"Elgato","a4:11:94":"Sonos","00:0e:58":"Sonos",
 "5c:aa:fd":"Sonos","34:7e:5c":"Sonos","b8:e9:37":"Sonos",
 "00:17:88":"Philips Hue","ec:b5:fa":"Philips Hue",
 "b0:ce:18":"Philips Hue",
 "b8:8a:60":"Intel","a0:36:9f":"Intel",
 "fc:f5:c4":"Espressif (ESP)","24:6f:28":"Espressif (ESP)",
 "3c:71:bf":"Espressif (ESP)","a4:cf:12":"Espressif (ESP)",
 "cc:50:e3":"Espressif (ESP)","84:cc:a8":"Espressif (ESP)",
 "94:b9:7e":"Espressif (ESP)","08:3a:f2":"Espressif (ESP)",
 "a0:20:a6":"Espressif (ESP)",
 "f0:9f:c2":"Ubiquiti","78:8a:20":"Ubiquiti","fc:ec:da":"Ubiquiti",
 "80:2a:a8":"Ubiquiti","24:5a:4c":"Ubiquiti","68:d7:9a":"Ubiquiti",
 "dc:9f:db":"Ubiquiti","e0:63:da":"Ubiquiti",
 "48:a9:8a":"Roku","dc:3a:5e":"Roku","b0:a7:37":"Roku",
 "cc:6d:a0":"Roku","d0:4d:2c":"Roku",
 "00:1a:79":"Nintendo","34:af:2c":"Nintendo","7c:bb:8a":"Nintendo",
 "58:2f:40":"Nintendo","e8:4e:ce":"Nintendo",
 "00:d9:d1":"Sony PS","28:3f:69":"Sony PS","a8:e3:ee":"Sony PS",
 "f8:46:1c":"Sony PS","70:66:55":"Sony PS",
 "60:45:cb":"Lenovo","98:fa:9b":"Lenovo","8c:16:45":"Lenovo",
 "50:7b:9d":"Lenovo","e8:2a:44":"Lenovo","00:50:b6":"Belkin",
 "c0:56:27":"Belkin","ec:1a:59":"Belkin",
 "e0:5f:45":"HP","10:60:4b":"HP","00:1a:4b":"HP",
 "3c:d9:2b":"HP","b0:5a:da":"HP","94:57:a5":"HP",
 "b4:b6:76":"HP","00:17:a4":"HP",
 "10:7b:ef":"Zyxel","d4:21:22":"Zyxel","78:a7:14":"Ampak/Realtek",
 "00:e0:4c":"Realtek","52:54:00":"QEMU/KVM","08:00:27":"VirtualBox",
 "00:25:90":"Supermicro","ac:1f:6b":"Supermicro",
 "b4:2e:99":"Gree/Tuya IoT","d8:f1:5b":"Tuya IoT",
 "70:b3:d5":"IEEE Registered",
 "00:11:32":"Synology","00:1b:21":"Intel",
 "40:8d:5c":"QNAP",
}

# Load full OUI database from file (39K+ entries), fall back to embedded
OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.tsv")
def _load_oui():
    db = dict(_OUI)  # start with embedded as base
    if os.path.exists(OUI_FILE):
        try:
            with open(OUI_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split("\t", 1)
                    if len(parts) == 2:
                        db[parts[0]] = parts[1]
            print(f"[TP] OUI database loaded: {len(db)} manufacturers")
        except Exception as e:
            print(f"[TP] OUI file error: {e}", file=sys.stderr)
    else:
        print(f"[TP] Using embedded OUI ({len(db)} entries). Place oui.tsv for full coverage.")
    return db

_OUI_FULL = _load_oui()

def lookup_vendor(mac):
    prefix = mac.replace(":","").upper()[:6]
    return _OUI_FULL.get(prefix, "")

def enhance_vendor(dev):
    """Refine vendor string based on other device clues."""
    v = dev.get("vendor", "")
    h = dev.get("hostname", "").lower()
    n = dev.get("nickname", "").lower()
    
    if not v:
        if any(x in h or x in n for x in ["ipad", "iphone", "apple", "macbook", "imac", "watch"]):
            return "Apple Inc."
        if "pixel" in h: return "Google"
        if "samsung" in h: return "Samsung"
        if "blink" in h: return "Amazon / Blink"
        if "nest" in h: return "Google / Nest"
    
    # ThinkPad ODM recognition
    if "wistron" in v.lower() or "compal" in v.lower():
        if dev.get("is_self") or "thinkpad" in h or "thinkpad" in n:
            return "ThinkPad"
            
    return v

# ─── Device Classification ──────────────────────────────────────────────────
_CATEGORIES = {
    "router":  ["gateway","router","access point","ubiquiti","mikrotik","cisco","linksys","tp-link","netgear","asus","arris","motorola"],
    "phone":   ["iphone","android","samsung","pixel","huawei","xiaomi","oppo","oneplus","galaxy"],
    "laptop":  ["macbook","laptop","surface","dell","hp","lenovo","thinkpad","notebook"],
    "desktop": ["imac","mac-pro","desktop","workstation","tower"],
    "tv":      ["smart-tv","bravia","vizio","webos","tizen","roku","firestick","chromecast","apple-tv","shield-tv","kodi","plex","toshiba","sharp","panasonic"],
    "iot":     ["sonos","hue","philips","tuya","shelly","esp32","arduino","tasmota","amazon","echo","google","nest","roku","ring","wyze","smart"],
    "server":  ["nas","synology","qnap","truenas","unraid","proxmox","esxi","ubuntu","debian","raspberry","pi","docker"],
    "printer": ["printer","canon","epson","brother","hp-print","jetdirect"],
    "gaming":  ["playstation","xbox","nintendo","switch","steam"],
}

def classify_device(dev):
    blob = " ".join([
        dev.get("hostname",""), dev.get("nickname",""), dev.get("vendor","")
    ]).lower()
    if dev.get("is_self"): return "laptop" 
    if "thinkpad" in blob: return "laptop"
    if "tv" in blob or "smart-tv" in blob: return "tv"
    if "ipad" in blob: return "tablet"
    if "iphone" in blob or "pixel" in blob: return "phone"
    if dev.get("ip","").endswith(".1") or any(k in blob for k in _CATEGORIES["router"]):
        return "router"
    for cat, kws in _CATEGORIES.items():
        if any(k in blob for k in kws):
            return cat
    ports = {p["port"] for p in dev.get("open_ports",[])}
    if ports & {8001, 8002, 9080, 7676, 1530}:
        return "tv"
    if ports & {22, 8006, 5000, 9090}:
        return "server"
    if ports & {631, 9100}:
        return "printer"
    return "other"

def security_score(dev):
    s = 100
    ports = {p["port"] for p in dev.get("open_ports",[])}
    if 23 in ports: s -= 50
    if 445 in ports: s -= 20
    if 80 in ports: s -= 10
    if 21 in ports: s -= 15
    if 8001 in ports or 8002 in ports: s -= 15
    if 554 in ports or 1935 in ports: s -= 10 # RTSP/RTMP video streams
    s -= len(ports) * 3
    return max(0, s)

def security_advice(dev):
    out = []
    ports = {p["port"] for p in dev.get("open_ports",[])}
    if 23 in ports: out.append({"level":"critical","msg":"Telnet (23) is open — unencrypted remote access. Disable immediately."})
    if 21 in ports: out.append({"level":"warning","msg":"FTP (21) is open — credentials sent in plain text. Use SFTP instead."})
    if 80 in ports: out.append({"level":"info","msg":"HTTP (80) detected — consider HTTPS for encrypted traffic."})
    if 445 in ports: out.append({"level":"warning","msg":"SMB (445) open — ensure it's not publicly exposed."})
    if 22 in ports: out.append({"level":"info","msg":"SSH (22) active — verify key-based auth is enforced."})
    
    if dev.get("category") == "tv":
        out.append({"level":"info","msg":"Smart TV detected. Ensure 'Automatic Updates' are enabled to patch unauthenticated remote control bugs."})
        if 8001 in ports or 8002 in ports:
            out.append({"level":"warning","msg":"Samsung Tizen remote control ports (8001/8002) are open. These can sometimes be used for unauthorized screen mirroring or volume control by anyone on your network."})
        if 554 in ports:
            out.append({"level":"critical","msg":"RTSP Video Stream (554) is open. This may allow anyone on the network to view the TV's screen or camera (if equipped)."})

    if not out and dev.get("online"):
        out.append({"level":"ok","msg":"No common vulnerabilities detected."})
    return out

def get_isp_info():
    global _isp_cache
    now = time.time()
    if _isp_cache["data"] and now < _isp_cache["expiry"]:
        return _isp_cache["data"]
    try:
        import urllib.request
        with urllib.request.urlopen("http://ip-api.com/json/", timeout=3) as r:
            d = json.load(r)
            info = {"public_ip":d.get("query","?"), "isp":d.get("isp","?"),
                    "city":d.get("city","?"), "country":d.get("country","?")}
            _isp_cache = {"data": info, "expiry": now + 3600}
            return info
    except Exception:
        return {"public_ip":"—","isp":"—","city":"—","country":"—"}

# ─── Name Resolution ────────────────────────────────────────────────────────
def resolve_name(ip):
    """Try multiple methods to find a human-readable name."""
    # avahi (Linux/Pi)
    try:
        r = subprocess.run(["avahi-resolve","-a",ip], capture_output=True, text=True, timeout=2)
        if r.returncode == 0:
            parts = r.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1].replace(".local","")
    except Exception: pass
    # reverse DNS
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception: pass
    return ""

# ─── Network Scanner ────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 443:"HTTPS", 445:"SMB", 631:"IPP", 3306:"MySQL",
    3389:"RDP", 5432:"PostgreSQL", 5000:"Dev/NAS", 5900:"VNC",
    8006:"Proxmox", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 9090:"Cockpit",
    9100:"Print"
}

def ping_latency(ip):
    try:
        if sys.platform == "win32":
            cmd = ["ping","-n","1","-w","1000",ip]
        else:
            cmd = ["ping","-c","1","-W","1",ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            m = re.search(r"time[=<](\d+\.?\d*)", r.stdout)
            if m: return round(float(m.group(1)), 1)
    except Exception: pass
    return None

def scan_ports(ip, timeout=0.4):
    # Try nmap first
    try:
        port_csv = ",".join(str(p) for p in COMMON_PORTS)
        r = subprocess.run(
            [NMAP_PATH,"-sV","--host-timeout","3s","-p",port_csv,ip],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and "/tcp" in r.stdout:
            found = []
            for line in r.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    pnum = int(parts[0].split("/")[0])
                    ver = " ".join(parts[3:]) if len(parts) > 3 else ""
                    found.append({"port":pnum, "label":COMMON_PORTS.get(pnum,"?"), "version":ver})
            return found
    except Exception: pass

    # Fallback: raw socket connect
    found = []
    for port, label in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    found.append({"port":port, "label":label, "version":""})
        except Exception: pass
    return found

def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def subnet():
    ip = local_ip()
    return ".".join(ip.split(".")[:-1]) + ".0/24"

def _is_local_ip(ip, prefix):
    """Return True if the IP is a local LAN address we care about."""
    # If it's a 192.168.x.x, we likely want it (as per user request)
    if ip.startswith("192.168."):
        # Still drop broadcast and junk
        if ip.endswith(".255") or ip.endswith(".0"): return False
        return True
        
    # Fallback to strict prefix matching for other private ranges
    if not ip.startswith(prefix):
        return False
        
    first = int(ip.split(".")[0])
    # Drop multicast (224-239), link-local (169.254), loopback (127), broadcast
    if first in (0, 127, 255) or 224 <= first <= 239:
        return False
    if ip.startswith("169.254."):
        return False
    return True

def _is_virtual_adapter(mac, vendor):
    """Filter out common virtual/ghost adapters from host software."""
    if not mac: return False
    # VMware virtual prefixes
    if mac.startswith(("00:50:56", "00:0c:29", "00:05:69")):
        return True
    if vendor and "VMware" in vendor:
        return True
    return False

def _get_nmap_path():
    """Find nmap binary path based on OS."""
    if sys.platform == "win32":
        paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        for p in paths:
            if os.path.exists(p): return p
    return "nmap"

NMAP_PATH = _get_nmap_path()

def discover_devices():
    """ARP + optional nmap discovery. Returns list of {ip, mac, hostname}."""
    found = {}  # ip -> {ip, mac, hostname}
    my_ip = local_ip()
    prefix = ".".join(my_ip.split(".")[:-1]) + "."  # e.g. "192.168.1."

    # Helper to get MAC from ARP if missing
    def _get_mac_for_ip(target_ip):
        try:
            r = subprocess.run(["arp", "-a", target_ip], capture_output=True, text=True, timeout=2)
            mac_m = re.search(r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", r.stdout)
            if mac_m:
                return mac_m.group(0).lower().replace("-", ":")
        except Exception: pass
        return None

    # ARP table (primary)
    try:
        r = subprocess.run(["arp","-a"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            ip_m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            mac_m = re.search(r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
            if ip_m and mac_m:
                ip = ip_m.group(0)
                mac = mac_m.group(0).lower().replace("-",":")
                if mac == "ff:ff:ff:ff:ff:ff": continue
                if not _is_local_ip(ip, prefix): continue
                found[ip] = {"ip":ip, "mac":mac, "hostname":""}
    except Exception: pass

    # nmap ping sweep (fill gaps)
    # We scan ALL detected local subnets to ensure we don't miss the real LAN
    subnets_to_scan = {subnet()} # Start with default
    try:
        # On Windows/Linux, find all 192.168.x.x or 10.x.x.x interfaces
        if sys.platform == "win32":
            cmd = ["ipconfig"]
        else:
            cmd = ["hostname","-I"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for ip in re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r.stdout):
            if ip.startswith(("192.168.", "10.", "172.")):
                if not ip.endswith((".1", ".255", ".0")):
                    subnets_to_scan.add(".".join(ip.split(".")[:-1]) + ".0/24")
    except Exception: pass

    for target_net in subnets_to_scan:
        try:
            # -PR uses ARP ping which is much more reliable on local LANs
            r = subprocess.run([NMAP_PATH,"-sn","-PR",target_net], capture_output=True, text=True, timeout=30)
            
            # DEBUG: Log nmap output to help diagnose missing devices
            with open("nmap_debug.log", "a") as f:
                f.write(f"\n--- Scan of {target_net} at {datetime.now()} ---\n")
                f.write(r.stdout)
                if r.stderr: f.write(f"\nERR: {r.stderr}")

            current_ip = None
            for line in r.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    current_ip = parts[-1].strip("()")
                    if not _is_local_ip(current_ip, prefix):
                        current_ip = None
                        continue
                    
                    hostname = ""
                    if len(parts) > 4 and not parts[4].startswith("("):
                        hostname = parts[4]
                    
                    if current_ip not in found:
                        found[current_ip] = {"ip":current_ip, "mac":None, "hostname":hostname}
                    elif hostname:
                        found[current_ip]["hostname"] = hostname
                elif "MAC Address:" in line and current_ip:
                    mac = line.split("MAC Address:")[1].strip().split()[0].lower().replace("-",":")
                    if current_ip in found:
                        found[current_ip]["mac"] = mac
        except Exception: pass

    # Final Pass: Ensure every device has a MAC or drop it (we can't index without MAC)
    results = []
    for ip, dev in found.items():
        if not dev.get("mac"):
            # Try to "wake" the ARP entry by doing a quick connect attempt
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    s.connect_ex((ip, 80)) # Port doesn't matter, just need to trigger ARP
            except: pass
            dev["mac"] = _get_mac_for_ip(ip)
        
        if dev.get("mac"):
            # Check for virtual adapters
            vendor = lookup_vendor(dev["mac"])
            if _is_virtual_adapter(dev["mac"], vendor):
                continue

            dev["is_self"] = (ip == my_ip)
            results.append(dev)
    
    # --- Self-Discovery Injection (Always include this machine) ---
    try:
        import uuid
        s_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 48, 8)][::-1])
        with open("nmap_debug.log", "a") as f:
            f.write(f"\n[SELF] IP:{my_ip} Host:{socket.gethostname()} MAC:{s_mac}\n")
        
        if not any(d["mac"] == s_mac for d in results):
            results.append({
                "ip": my_ip, 
                "mac": s_mac, 
                "hostname": socket.gethostname(), 
                "is_self": True
            })
        else:
            for d in results:
                if d["mac"] == s_mac: d["is_self"] = True
    except Exception as e:
        with open("nmap_debug.log", "a") as f:
            f.write(f"\n[SELF ERR] {e}\n")

    return results

# ─── API Security ───────────────────────────────────────────────────────────
RE_MAC = re.compile(r"^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$", re.I)
RE_IP  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tp_token.txt")
def _get_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f: return f.read().strip()
    import secrets
    t = secrets.token_hex(16)
    with open(TOKEN_FILE, "w") as f: f.write(t)
    return t

API_TOKEN = _get_token()

# ─── Intelligence Hub ────────────────────────────────────────────────────────
def process_scan(raw_devices):
    """Unified scan processor. Runs name resolution OUTSIDE the lock."""
    global _latest_scan, _scan_timestamp, _was_online
    now = datetime.now().isoformat()

    # Phase 1: Resolve names outside the lock (network I/O)
    for dev in raw_devices:
        if not dev.get("hostname"):
            dev["hostname"] = resolve_name(dev["ip"])

    # Phase 2: Latency outside the lock
    latencies = {}
    for dev in raw_devices:
        latencies[dev["mac"]] = ping_latency(dev["ip"])

    # Phase 3: Update state under lock
    found_macs = {d["mac"] for d in raw_devices}

    with _lock:
        data = load_data()
        prev_online = {mac: d.get("online", False) for mac, d in data["devices"].items()}

        # Mark everything offline
        for mac in data["devices"]:
            data["devices"][mac]["online"] = False

        for dev in raw_devices:
            mac = dev["mac"]
            lat = latencies.get(mac)

            if mac in data["devices"]:
                d = data["devices"][mac]
                was = prev_online.get(mac, False)

                # ONLINE event: was offline, now found
                if not was:
                    d.setdefault("events", []).append({"type":"ONLINE","ts":now})

                d["ip"] = dev["ip"]
                d["hostname"] = dev["hostname"] or d.get("hostname","")
                d["last_seen"] = now
                d["online"] = True
                d["is_self"] = dev.get("is_self", False)
                # Backfill/Enhance vendor (preserve existing high-fidelity vendor)
                new_v = enhance_vendor(d)
                if not d.get("vendor") or (new_v and len(new_v) > len(d.get("vendor",""))):
                    d["vendor"] = new_v
                # Clear "new" flag after first re-appearance
                if d.get("new") and was:
                    d["new"] = False

                # Latency
                d.setdefault("latency_history", [])
                if lat is not None:
                    d["latency_history"].append(lat)
                    d["latency_history"] = d["latency_history"][-20:]
                d["last_latency"] = lat

                # Intelligence
                d["category"] = classify_device(d)
                d["security_score"] = security_score(d)
                d["security_advice"] = security_advice(d)
            else:
                # DIGITAL FENCE: brand new device never seen before
                mac_v = lookup_vendor(mac)
                new = {
                    "ip":dev["ip"], "mac":mac,
                    "hostname":dev["hostname"], "vendor":mac_v,
                    "nickname":"", "notes":"",
                    "first_seen":now, "last_seen":now,
                    "online":True, "is_self":dev.get("is_self",False),
                    "latency_history":[lat] if lat else [],
                    "last_latency":lat,
                    "open_ports":[], "category":"other",
                    "security_score":100, "security_advice":[],
                    "events":[{"type":"ONLINE","ts":now}],
                    "new":True
                }
                new["vendor"] = enhance_vendor(new)
                new["category"] = classify_device(new)
                data["devices"][mac] = new

        # OFFLINE events: was online last scan, not found this scan
        for mac, d in data["devices"].items():
            was = prev_online.get(mac, False)
            if was and mac not in found_macs:
                d.setdefault("events", []).append({"type":"OFFLINE","ts":now})

        # Trim events per device
        for d in data["devices"].values():
            if "events" in d:
                d["events"] = d["events"][-50:]

        data["scan_history"].append({"timestamp":now, "device_count":len(raw_devices)})
        data["scan_history"] = data["scan_history"][-100:]

        save_data(data)
        _latest_scan = list(data["devices"].values())
        _scan_timestamp = now

def background_scanner():
    # Small initial delay so the server can start before first scan
    time.sleep(2)
    while True:
        if _scanning.acquire(blocking=False):
            try:
                raw = discover_devices()
                process_scan(raw)
            except Exception as e:
                print(f"[TP] Scan error: {e}", file=sys.stderr)
            finally:
                _scanning.release()
        time.sleep(_config["scan_interval"])

# ─── HTTP Handler ────────────────────────────────────────────────────────────
class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access log spam

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body)))
        # Security Headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' fonts.googleapis.com fonts.gstatic.com")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n).decode("utf-8") if n > 0 else ""

    def _is_auth(self):
        # For home use, we'll auto-auth the local browser via a simple cookie or header
        # If the user is on the same machine, they are likely safe
        host = self.client_address[0]
        if host in ("127.0.0.1", "::1"): return True
        # Otherwise require token
        return self.headers.get("X-TP-Token") == API_TOKEN

    # ── GET ──
    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            try:
                with open(HTML_FILE,"rb") as f: content = f.read()
                self.send_response(200)
                self.send_header("Content-Type","text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404)
            return

        if path == "/api/devices":
            with _lock: data = load_data()
            devs = sorted(data["devices"].values(),
                          key=lambda d: (not d.get("online",False), d.get("ip","")))
            
            # Network-wide security score
            online_devs = [d for d in devs if d.get("online")]
            if online_devs:
                net_score = round(sum(d.get("security_score",100) for d in online_devs) / len(online_devs))
            else:
                net_score = 100
            new_count = sum(1 for d in devs if d.get("new"))

            self._json({
                "devices": devs,
                "scan_timestamp": _scan_timestamp,
                "local_ip": local_ip(),
                "subnet": subnet(),
                "isp_info": get_isp_info(),
                "online": sum(1 for d in online_devs),
                "offline": len(devs) - len(online_devs),
                "scan_interval": _config["scan_interval"],
                "network_score": net_score,
                "new_devices": new_count,
                "last_speed": _config.get("last_speed"),
                "token_required": self.client_address[0] not in ("127.0.0.1", "::1")
            })
            return

        if path == "/api/history":
            with _lock: data = load_data()
            self._json({"history": data.get("scan_history",[])})
            return

        if path == "/api/scan":
            def _do():
                if _scanning.acquire(blocking=False):
                    try: process_scan(discover_devices())
                    finally: _scanning.release()
            threading.Thread(target=_do, daemon=True).start()
            self._json({"status":"ok"})
            return

        if path == "/api/export/csv":
            with _lock: data = load_data()
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["Nickname","Hostname","IP","MAC","Category","Status","Score","Open Ports","First Seen","Last Seen"])
            for mac, d in data["devices"].items():
                ports = ", ".join(f"{p['port']}/{p['label']}" for p in d.get("open_ports",[]))
                w.writerow([d.get("nickname",""),d.get("hostname",""),d.get("ip",""),
                            mac, d.get("category",""), "Online" if d.get("online") else "Offline",
                            d.get("security_score",100), ports,
                            d.get("first_seen",""), d.get("last_seen","")])
            body = buf.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","text/csv")
            self.send_header("Content-Disposition","attachment; filename=tracketpacket_export.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404)

    # ── POST ──
    def do_POST(self):
        if not self._is_auth():
            return self._json({"error":"unauthorized"}, 401)

        path = self.path
        try:
            body = self._read_body()
            p = json.loads(body) if body else {}
        except Exception:
            return self._json({"error":"invalid json"}, 400)

        if path == "/api/device/update":
            mac = p.get("mac","")
            if not RE_MAC.match(mac): return self._json({"error":"invalid mac"}, 400)
            
            with _lock:
                data = load_data()
                if mac in data["devices"]:
                    if "nickname" in p: data["devices"][mac]["nickname"] = str(p["nickname"])[:64]
                    if "notes" in p:    data["devices"][mac]["notes"] = str(p["notes"])[:256]
                    data["devices"][mac]["category"] = classify_device(data["devices"][mac])
                    save_data(data)
            return self._json({"status":"ok"})

        if path == "/api/interval":
            val = int(p.get("interval", 60))
            if val in ALLOWED_INTERVALS:
                _config["scan_interval"] = val
            return self._json({"status":"ok","interval":_config["scan_interval"]})

        if path == "/api/device/scan_ports":
            mac = p.get("mac","")
            if not RE_MAC.match(mac): return self._json({"error":"invalid mac"}, 400)
            with _lock:
                dev = load_data()["devices"].get(mac)
            if not dev: return self._json({"error":"not found"}, 404)
            
            def _run():
                ports = scan_ports(dev["ip"])
                with _lock:
                    data = load_data()
                    if mac in data["devices"]:
                        d = data["devices"][mac]
                        d["open_ports"] = ports
                        d["security_score"] = security_score(d)
                        d["security_advice"] = security_advice(d)
                        save_data(data)
            threading.Thread(target=_run, daemon=True).start()
            return self._json({"status":"running"})

        if path == "/api/device/ping":
            ip = p.get("ip","")
            if not RE_IP.match(ip): return self._json({"error":"invalid ip"}, 400)
            return self._json({"latency": ping_latency(ip)})

        if path == "/api/device/wol":
            mac = p.get("mac","")
            if not RE_MAC.match(mac): return self._json({"error":"invalid mac"}, 400)
            try:
                mac_b = bytes.fromhex(mac.replace(":","").replace("-",""))
                pkt = b"\xff"*6 + mac_b*16
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(pkt, ("255.255.255.255", 9))
                return self._json({"status":"ok"})
            except Exception as e:
                return self._json({"error":str(e)}, 400)

        if path == "/api/history/clear":
            print("[TP] Wiping activity logs...")
            with _lock:
                data = load_data()
                for d in data["devices"].values():
                    d["events"] = []
                data["scan_history"] = []
                save_data(data)
            return self._json({"status":"ok"})

        if path == "/api/network/audit":
            def _audit():
                with _lock:
                    targets = [(m, d["ip"]) for m, d in load_data()["devices"].items() if d.get("online")]
                for mac, ip in targets:
                    ports = scan_ports(ip)
                    with _lock:
                        data = load_data()
                        if mac in data["devices"]:
                            d = data["devices"][mac]
                            d["open_ports"] = ports
                            d["security_score"] = security_score(d)
                            d["security_advice"] = security_advice(d)
                            save_data(data)
                    time.sleep(0.5)
            threading.Thread(target=_audit, daemon=True).start()
            return self._json({"status":"running"})

        if path == "/api/network/speedtest":
            def _speed():
                try:
                    import urllib.request
                    # 1. Download Test (10MB)
                    d_url = "https://speed.cloudflare.com/__down?bytes=10000000"
                    t0 = time.time()
                    with urllib.request.urlopen(d_url, timeout=30) as r:
                        _ = r.read()
                    d_mbps = (80 / (time.time() - t0))
                    
                    # 2. Upload Test (5MB)
                    u_url = "https://speed.cloudflare.com/__up"
                    payload = b'0' * 5000000
                    t1 = time.time()
                    req = urllib.request.Request(u_url, data=payload, method='POST')
                    with urllib.request.urlopen(req, timeout=30) as r:
                        _ = r.read()
                    u_mbps = (40 / (time.time() - t1))

                    with _lock:
                        _config["last_speed"] = {
                            "down": round(d_mbps, 2),
                            "up": round(u_mbps, 2),
                            "ts": datetime.datetime.now().isoformat()
                        }
                except Exception as e:
                    print(f"[TP] Speedtest fail: {e}", file=sys.stderr)
            threading.Thread(target=_speed, daemon=True).start()
            return self._json({"status":"running"})

        self.send_error(404)

# ─── Dependency Checker ──────────────────────────────────────────────────────
def _check_tool(name):
    """Return True if a CLI tool is available."""
    try:
        cmd = [NMAP_PATH] if name == "nmap" else [name]
        subprocess.run(cmd + ["--version"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False

def _first_run_check():
    """Check for optional dependencies and offer to install them."""
    missing = []

    if not _check_tool("nmap"):
        missing.append(("nmap", "Deep network scanning & service detection"))

    # avahi only matters on Linux
    if sys.platform != "win32" and not _check_tool("avahi-resolve"):
        missing.append(("avahi-utils", "mDNS device name resolution"))

    if not missing:
        print("  [OK] All optional tools installed\n")
        return

    print("  --- Optional Dependencies ---")
    for pkg, desc in missing:
        print(f"  [MISSING] {pkg:16s} - {desc}")
    print()

    # Detect package manager
    if sys.platform == "win32":
        mgr = "choco"
        mgr_name = "choco install"
    elif os.path.exists("/usr/bin/apt"):
        mgr = "apt"
        mgr_name = "sudo apt install -y"
    elif os.path.exists("/usr/bin/brew") or os.path.exists("/opt/homebrew/bin/brew"):
        mgr = "brew"
        mgr_name = "brew install"
    elif os.path.exists("/usr/bin/dnf"):
        mgr = "dnf"
        mgr_name = "sudo dnf install -y"
    elif os.path.exists("/usr/bin/pacman"):
        mgr = "pacman"
        mgr_name = "sudo pacman -S --noconfirm"
    else:
        print(f"  Install manually: {', '.join(p for p,_ in missing)}")
        print("  TracketPacket will run without them (reduced accuracy).\n")
        return

    pkg_names = " ".join(p for p, _ in missing)
    # On Windows, nmap choco package name is just "nmap"
    # On apt, avahi package is "avahi-utils"
    print(f"  Install with: {mgr_name} {pkg_names}")

    try:
        answer = input("  Install now? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer == "y":
        for pkg, _ in missing:
            print(f"  Installing {pkg}...")
            try:
                if mgr == "apt":
                    subprocess.run(["sudo", "apt", "install", "-y", pkg], check=True)
                elif mgr == "brew":
                    subprocess.run(["brew", "install", pkg], check=True)
                elif mgr == "dnf":
                    subprocess.run(["sudo", "dnf", "install", "-y", pkg], check=True)
                elif mgr == "pacman":
                    subprocess.run(["sudo", "pacman", "-S", "--noconfirm", pkg], check=True)
                elif mgr == "choco":
                    subprocess.run(["choco", "install", pkg, "-y"], check=True)
                print(f"  [OK] {pkg} installed")
            except Exception as e:
                print(f"  [FAIL] {pkg} install failed: {e}")
    else:
        print("  Skipped — TracketPacket will run with reduced accuracy.\n")

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    port = PORT
    if "--port" in sys.argv:
        try: port = int(sys.argv[sys.argv.index("--port")+1])
        except (IndexError, ValueError): pass

    ip = local_ip()
    print(f"\n  TracketPacket v4")
    print(f"  http://{ip}:{port}")
    print(f"  Subnet: {subnet()}  |  Interval: {_config['scan_interval']}s\n")

    # Only check dependencies in interactive terminals
    if sys.stdin.isatty():
        _first_run_check()

    threading.Thread(target=background_scanner, daemon=True).start()

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[TP] Shutdown.")
        server.shutdown()

if __name__ == "__main__":
    main()
