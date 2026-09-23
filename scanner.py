import logging
import socket
import struct
from scapy.all import ARP, Ether, srp, IP, TCP, ICMP, sr1, conf

# Disable scapy verbose logging
# TR: Scapy'nin gereksiz ekrana yazı basmasını kapatıyoruz.
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkScanner:
    def __init__(self, interface=None, detector=None):
        self.interface = interface
        self.detector = detector
        # TR: Yaygın MAC adres üreticileri sözlüğü. (OUI Lookup)
        # Simple dictionary to guess the vendor from the first 3 bytes of MAC.
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
        Attempts to determine the local subnet string (e.g., 192.168.1.0/24)
        TR: Yerel ağ bloğunu otomatik bulur.
        """
        try:
            # Create a dummy socket to connect outside, getting the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            # Assume /24 for local home networks
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def get_vendor(self, mac):
        """
        Extracts vendor info based on MAC address prefix.
        TR: MAC adresinin başından cihaz üreticisini tahmin eder.
        """
        mac_prefix = mac.upper()[:8]
        return self.mac_vendors.get(mac_prefix, "Unknown")

    def guess_os(self, ip):
        """
        Guesses the OS based on the Time-To-Live (TTL) value from a ping response.
        TR: Cihaza ping atıp dönen TTL süresine göre işletim sistemini tahmin eder.
        """
        try:
            # Send an ICMP echo request (ping)
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp:
                ttl = resp.ttl
                # Linux typically has TTL=64, Windows=128, Cisco=255
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
        Scans a list of common ports to see if they are open.
        TR: Cihazın yaygın kapılarını (port) tarar.
        """
        open_ports = []
        try:
            for port in self.common_ports:
                # Create a TCP SYN packet
                pkt = IP(dst=ip)/TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=0.2, verbose=0)
                # If we get a response and the flags contain 'SA' (SYN-ACK)
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                    open_ports.append(port)
                    # Send RST to close the connection properly
                    sr1(IP(dst=ip)/TCP(dport=port, flags="AR"), timeout=0.2, verbose=0)
        except Exception:
            pass
        return open_ports

    def scan_network(self, target_ip=None):
        """
        Performs an ARP scan to discover devices on the network.
        TR: Ağa 'Kimler burda?' diye sorar (ARP Scan) ve cihazları bulur.
        """
        if not target_ip:
            target_ip = self.get_local_subnet()
            
        print(f"[Scanner] Scanning network: {target_ip}")
        
        # Craft an ARP request to the broadcast MAC address
        # TR: ARP isteği hazırlayıp tüm ağa yollarız.
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and capture responses
        # TR: Paketi gönder ve cevapları dinle.
        result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]

        devices = []
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            
            # Try to resolve hostname
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
            
            # Pass device to detector for analysis
            if self.detector:
                self.detector.analyze_device(device_info)

        return devices
