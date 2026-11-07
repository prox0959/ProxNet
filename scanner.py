import logging
import socket
import struct
import subprocess
import re

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, ICMP, sr1, conf
    conf.verb = 0
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


class NetworkScanner:
    def __init__(self, interface=None, detector=None):
        self.interface = interface
        self.detector = detector
        # Common MAC vendor OUI prefixes
        self.mac_vendors = {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "00:1A:11": "Google",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "00:15:5D": "Microsoft",
            "4C:79:08": "Apple",
            "C8:69:CD": "Apple",
            "28:CF:E9": "Apple",
            "E8:4E:06": "Intel",
            "F8:59:71": "Intel",
            "04:52:F3": "Samsung"
        }
        self.common_ports = [22, 80, 443, 445, 3389, 8080]

    def get_local_subnet(self):
        """
        Determines the local IPv4 subnet (e.g., 192.168.1.0/24).
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def get_vendor(self, mac):
        """
        Extracts vendor info based on MAC address prefix.
        """
        mac_norm = mac.upper().replace("-", ":")[:8]
        return self.mac_vendors.get(mac_norm, "Unknown")

    def guess_os(self, ip):
        """
        Guesses the OS based on the Time-To-Live (TTL) value from a ping response.
        """
        if HAS_SCAPY:
            try:
                pkt = IP(dst=ip) / ICMP()
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp:
                    ttl = resp.ttl
                    if ttl <= 64:
                        return "Linux/Unix/Mac"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Network Device (Cisco/Router)"
            except Exception:
                pass
        return "Unknown OS"

    def scan_ports(self, ip):
        """
        Scans a list of common ports using TCP SYN (Scapy) or standard TCP connect fallback.
        """
        open_ports = []
        if HAS_SCAPY:
            try:
                for port in self.common_ports:
                    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
                    resp = sr1(pkt, timeout=0.2, verbose=0)
                    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                        open_ports.append(port)
                        sr1(IP(dst=ip) / TCP(dport=port, flags="AR"), timeout=0.2, verbose=0)
                return open_ports
            except Exception:
                pass

        # Fallback: Native TCP socket connect scan (requires no Npcap driver)
        for port in self.common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.15)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        return open_ports

    def _scan_arp_table_fallback(self):
        """
        Fallback ARP table parser using OS `arp -a` when Npcap/WinPcap is unavailable.
        """
        discovered = []
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, errors="ignore")
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
                    if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.") or mac == "ff:ff:ff:ff:ff:ff":
                        continue
                    discovered.append((ip, mac))
        except Exception:
            pass
        return discovered

    def scan_network(self, target_ip=None):
        """
        Performs an ARP scan to discover devices on the network, with automatic OS ARP fallback.
        """
        if not target_ip:
            target_ip = self.get_local_subnet()

        print(f"[Scanner] Scanning network: {target_ip}")
        raw_pairs = []

        if HAS_SCAPY:
            try:
                arp = ARP(pdst=target_ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]
                for _, received in result:
                    raw_pairs.append((received.psrc, received.hwsrc))
            except Exception as e:
                print(f"[Scanner] Layer-2 raw socket unavailable ({e}), using OS ARP cache fallback...")

        if not raw_pairs:
            raw_pairs = self._scan_arp_table_fallback()

        devices = []
        for ip, mac in raw_pairs:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"

            vendor = self.get_vendor(mac)
            os_guess = self.guess_os(ip)
            open_ports = self.scan_ports(ip)

            device_info = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "os": os_guess,
                "open_ports": open_ports
            }
            devices.append(device_info)

            if self.detector:
                self.detector.analyze_device(device_info)

        return devices
