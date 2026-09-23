import time
from datetime import datetime

class ThreatDetector:
    def __init__(self):
        # Keeps track of known devices by MAC address
        # TR: MAC adreslerini kullanarak bildiğimiz cihazları hatırlarız.
        self.known_devices = {}
        
        # Keeps track of all threats detected
        # TR: Tespit edilen tehditleri bir listede tutarız.
        self.threat_log = []
        
        # To detect IP conflicts / ARP Spoofing
        self.ip_to_mac = {}

    def log_threat(self, device_ip, severity, message):
        """
        Adds a new threat to the log.
        TR: Yeni bir tehdidi (uyarıyı) kayıt defterine ekler.
        """
        threat = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": device_ip,
            "severity": severity,
            "message": message
        }
        self.threat_log.append(threat)
        print(f"[Threat Detector] [{severity}] {device_ip}: {message}")

    def analyze_device(self, device):
        """
        Checks a device for suspicious activity.
        TR: Bir cihazı şüpheli durumlara karşı kontrol eder (Kurallar).
        """
        ip = device['ip']
        mac = device['mac']
        ports = device['open_ports']

        # RULE 1: New Device Detection
        # TR: Kural 1: Ağa yeni bir cihaz mı bağlandı?
        if mac not in self.known_devices:
            if len(self.known_devices) > 0: # Don't alert on very first scan
                self.log_threat(ip, "INFO", "New device appeared on network.")
            self.known_devices[mac] = device
        
        # RULE 2: ARP Spoofing Detection (IP address used by different MAC)
        # TR: Kural 2: ARP Zehirlenmesi (Biri başkasının IP'sini çalıyor mu?)
        if ip in self.ip_to_mac and self.ip_to_mac[ip] != mac:
            self.log_threat(ip, "CRITICAL", f"Possible ARP Spoofing! IP conflict. MAC changed from {self.ip_to_mac[ip]} to {mac}.")
        else:
            self.ip_to_mac[ip] = mac

        # RULE 3: Suspicious Ports (e.g., 445 SMB, 3389 RDP)
        # TR: Kural 3: Tehlikeli portlar açık mı? (Hackerların sevdiği portlar)
        suspicious_ports = [445, 3389]
        for port in ports:
            if port in suspicious_ports:
                self.log_threat(ip, "WARNING", f"Suspicious port {port} is open. Could be vulnerable.")
        
        # RULE 4: Too many open ports (Possible scanner)
        # TR: Kural 4: Çok fazla portu açık olan cihaz (Tarayıcı veya enfekte olmuş olabilir)
        if len(ports) >= 4:
            self.log_threat(ip, "WARNING", f"Device has many open ports ({len(ports)}). Ensure it's intentional.")

    def get_threats(self):
        """
        Returns the list of threats.
        TR: Tehdit listesini döndürür.
        """
        return self.threat_log
