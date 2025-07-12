import scapy.all as scapy
import socket
import requests
import psutil
import ipaddress
import threading
from queue import Queue
from flask import Blueprint, jsonify, request

net_scan_bp = Blueprint('net_scan', __name__)

class NetworkScanner:
    def __init__(self, IP):
        self.IP = IP
        self.queue = Queue()
        self.devices = []

    def resolve_mac_vendor(self, mac_address):
        url = f"https://api.macvendors.com/{mac_address}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.text.strip()
            else:
                return "Failed to retrieve vendor information"
        except requests.RequestException:
            return "Request error"

    def scan_ip(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = broadcast / arp_request
        answered = scapy.srp(packet, timeout=1, verbose=False)[0]

        for response in answered:
            ip_address = response[1].psrc
            mac_address = response[1].hwsrc

            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                hostname = "Unknown"

            vendor = self.resolve_mac_vendor(mac_address)

            self.queue.put({
                "IP": ip_address,
                "MAC": mac_address,
                "Hostname": hostname,
                "Vendor": vendor
            })

    def scan(self):
        ip_network = ipaddress.ip_network(self.IP + "/24", strict=False)
        threads = []

        for ip in ip_network.hosts():
            thread = threading.Thread(target=self.scan_ip, args=(str(ip),))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        while not self.queue.empty():
            self.devices.append(self.queue.get())

        return self.devices

    @staticmethod
    def get_interfaces():
        interfaces = []
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append({"interface": iface, "ip": addr.address})
        return interfaces

# Flask routes

@net_scan_bp.route('/interfaces', methods=['GET'])
def list_interfaces():
    return jsonify(NetworkScanner.get_interfaces())

@net_scan_bp.route('/scan', methods=['POST'])
def scan_network():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "Missing IP address"}), 400
    scanner = NetworkScanner(ip)
    devices = scanner.scan()
    return jsonify(devices)
