from flask import Flask, jsonify
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

@app.route('/')
def home():
    # Network scanning logic
    target_ip = "192.168.1.1/24"  # Change this to your network range
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return jsonify(devices)

if __name__ == '__main__':
    app.run(debug=True)
