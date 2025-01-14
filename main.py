from flask import Flask, render_template
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan')
def scan():
    # Network scanning logic
    target_ip = "192.168.1.1/24"  # Change this to your network range
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for _, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return render_template('scan.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
