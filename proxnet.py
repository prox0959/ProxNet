import argparse
import sys
import os
import threading
import time
from dashboard import start_dashboard, init_app
from scanner import NetworkScanner
from detector import ThreatDetector

# TR: Bu ana dosyamız. Projeyi başlatmak için kullanılır.
# This is our main entry point. It parses arguments and starts the modules.

def check_admin():
    """
    Check if the script is running with administrative privileges.
    TR: Yönetici yetkileriyle çalışıp çalışmadığını kontrol eder.
    """
    try:
        # For Windows
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # For Linux/Mac
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def print_banner():
    """
    Prints a cool ASCII art banner.
    TR: Ekrana havalı bir ASCII yazı basar.
    """
    banner = r"""
    ____  ____  ____  _  _  _  _  ____  ____ 
   (  _ \(  _ \(  _ \( \/ )( \( )(  __)(_  _)
    )___/ )   / )(_) ) )(  /    \ ) _)   )(  
   (__)  (__\_)(____/(_/\_)\_)__)(____) (__) 
   --- AI-Powered Network Threat Visualizer ---
    """
    print(banner)

def main():
    # TR: Kullanıcıdan ağ arayüzü ve port gibi ayarları alırız.
    # Parse command-line arguments for flexibility.
    parser = argparse.ArgumentParser(description="ProxNet - Network Threat Visualizer")
    parser.add_argument("--interface", help="Network interface to scan (e.g., eth0, Ethernet)", default=None)
    parser.add_argument("--port", type=int, help="Port for the web dashboard", default=5000)
    args = parser.parse_args()

    print_banner()

    if not check_admin():
        print("[!] WARNING: You are not running as Administrator/root.")
        print("[!] Scapy requires admin privileges to send ARP packets and sniff network traffic.")
        print("[!] Please restart your terminal/command prompt as Administrator.")
        print("[!] TR: Lütfen yönetici olarak çalıştırın! Ağ taraması yetki gerektirir.")
        sys.exit(1)

    print("[+] Admin privileges confirmed. Starting ProxNet...")

    # TR: Tarayıcı ve dedektör modüllerini oluştur.
    # Initialize core components
    detector = ThreatDetector()
    scanner = NetworkScanner(interface=args.interface, detector=detector)

    # TR: Flask uygulamasını bağla.
    # Initialize the dashboard app with our scanner and detector
    app, socketio = init_app(scanner, detector)

    # TR: Arka planda sürekli tarama yapacak fonksiyon.
    # Background thread to run continuous scans
    def scan_loop():
        while True:
            print("[*] Running background scan...")
            devices = scanner.scan_network()
            # Let the dashboard know we have new data
            socketio.emit('update_network', {'devices': devices}, namespace='/')
            # Wait for 30 seconds before next scan
            time.sleep(30)
            
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()

    # TR: Web sunucusunu başlat.
    # Start the web server
    print(f"[+] Starting web dashboard on port {args.port}...")
    start_dashboard(app, socketio, port=args.port)

if __name__ == "__main__":
    main()
