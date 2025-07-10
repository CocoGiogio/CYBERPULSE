# modules/sec_mod/packet_sniffer.py
import scapy.all as scapy
from scapy.layers import http
import threading

class Sniffing:
    def __init__(self, interface):
        self.interface = interface
        self.sniffing = False
        self.logs = []
        self.keywords = self.load_keywords("modules/sec_mod/sniffing_wordlists/keywords.txt")

    def load_keywords(self, file_path):
        try:
            with open(file_path, 'r') as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            return []

    def get_url(self, packet):
        try:
            return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        except Exception:
            return "Unknown URL"

    def get_info(self, packet):
        if packet.haslayer(scapy.Raw):
            try:
                load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                for keyword in self.keywords:
                    if keyword in load:
                        return load
            except Exception:
                pass
        return None

    def process_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet)
            self.logs.append(f"[HTTP] Visited URL: {url}")
            info = self.get_info(packet)
            if info:
                self.logs.append(f"[+] Sensitive Info Found: {info}")

    def sniff_packets(self):
        self.sniffing = True
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)

    def start_sniffing(self):
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True
        thread.start()

    # ✅ Add this missing method
    def get_logs(self):
        return self.logs
