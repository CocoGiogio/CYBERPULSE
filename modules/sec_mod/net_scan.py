import scapy.all as scapy
import socket
import requests

class NetworkScanner:
    def __init__(self, IP):
        self.IP = IP       

    def scan(self):
        target = self.IP + "/24"
        request = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        request_broadcast = broadcast / request

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
