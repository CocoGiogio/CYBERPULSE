# network_scanner.py
import threading
from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
from src.cyber_sec.port_scanner import PortScanner
import socket

class NetworkScanner:
    def get_network_info(self):
        default_gateways = psutil.net_if_addrs()
        selected_interface = None

        for iface, addrs in default_gateways.items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    selected_interface = iface
                    break
            if selected_interface:
                break

        if not selected_interface:
            return None

        ip_info = next(
            addr
            for addr in psutil.net_if_addrs()[selected_interface]
            if addr.family == socket.AF_INET
        )
        ip_address = ip_info.address
        subnet_mask = ip_info.netmask
        network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
        return str(network), selected_interface

    def perform_network_scan(self, ip_range, selected_interface, progress, root):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, iface=selected_interface, timeout=3, verbose=0)[0]
        devices = []
        total_addresses = len(list(ipaddress.IPv4Network(ip_range).hosts()))
        progress["maximum"] = total_addresses

        for i, (_, received) in enumerate(result):
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
            progress["value"] = i + 1
            root.update_idletasks()

        return devices

    def is_ip_reachable(self, ip):
        try:
            socket.create_connection((ip, 80), timeout=2)
            return True
        except OSError:
            return False
