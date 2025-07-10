import scapy.all as scapy
import socket
import requests
import psutil
from flask import Blueprint, jsonify, request

net_scan_bp = Blueprint('net_scan', __name__)

class NetworkScanner:
    def __init__(self, IP):
        self.IP = IP       

    def scan(self):
        target = self.IP + "/24"
        request_arp = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        request_broadcast = broadcast / request_arp

        clients = scapy.srp(request_broadcast, timeout=1, verbose=False)[0]

        devices = []
        for element in clients:
            mac_address = element[1].hwsrc
            ip_address = element[1].psrc

            url = f"https://api.macvendors.com/{mac_address}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    vendor_info = response.text.strip()
                    if vendor_info != "404":
                        vendor = vendor_info
                    else:
                        vendor = "Vendor not found"
                else:
                    vendor = "Failed to retrieve vendor information"
            except requests.RequestException:
                vendor = "Request error"

            devices.append({"IP": ip_address, "MAC": mac_address, "Vendor": vendor})

        return devices

    def get_interfaces():
        interfaces = []
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    interfaces.append({"interface": iface, "ip": addr.address})
        return interfaces

    @net_scan_bp.route('/interfaces', methods=['GET'])
    def list_interfaces():
        return jsonify(get_interfaces())

    @net_scan_bp.route('/scan', methods=['POST'])
    def scan_network():
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({"error": "Missing IP address"}), 400
        scanner = NetworkScanner(ip)
        devices = scanner.scan()
        return jsonify(devices) 