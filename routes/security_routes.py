from flask import Blueprint, render_template, request
from modules.sec_mod.directory_enum import DirectoryEnumeration
from modules.sec_mod.net_scan import NetworkScanner
from modules.sec_mod.mitm import MITM
from modules.sec_mod.sniffing import Sniffing
import os
import threading

# Define BASE_DIR at the top
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

security_bp = Blueprint('security', __name__, url_prefix='/security')

# Network Scan
@security_bp.route('/net_scan', methods=['GET', 'POST'])
def net_scan():
    results = None
    interfaces = NetworkScanner.get_interfaces()  # récupère les interfaces réseau

    if request.method == 'POST':
        IP = request.form.get('IP')
        if IP:
            scanner = NetworkScanner(IP)
            results = scanner.scan()
    return render_template('security/net_scan.html', results=results, interfaces=interfaces)

# Port Scanner
@security_bp.route('/port_scan')
def port_scan():
    return render_template('security/port_scan.html')

# keep instances global so you can fetch their logs
current_mitm = None
current_sniffer = None

# Port Scanner
@security_bp.route('/mitm_sniffing', methods=['GET', 'POST'])
def mitm_sniffing():
    global current_mitm, current_sniffer

    if request.method == 'POST':
        if 'gatewayIP' in request.form:
            # start MITM
            gw = request.form['gatewayIP']
            mitm = MITM(gw)
            thread = threading.Thread(target=mitm.start, daemon=True)
            thread.start()
            current_mitm = mitm

        elif 'interface' in request.form:
            # start sniffing
            iface = request.form['interface']
            sniffer = Sniffing(iface)
            thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
            thread.start()
            current_sniffer = sniffer

    # on GET and after POST, render and show logs
    mitm_logs = current_mitm.get_logs() if current_mitm else []
    sniff_logs = current_sniffer.get_logs() if current_sniffer else []

    return render_template('security/mitm_sniffing.html',
                           mitm_logs=mitm_logs,
                           sniff_logs=sniff_logs)



# Directory Enumeration
@security_bp.route('/directory_enum', methods=['GET', 'POST'])
def directory_enum():
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        wordlist = request.form.get('Wordlists')  # match your HTML <select> name

        wordlist_path = None
        if wordlist == 'big.txt':
            wordlist_path = os.path.join(BASE_DIR, '../modules/sec_mod/wordlists/big.txt')
        elif wordlist == 'common.txt':
            wordlist_path = os.path.join(BASE_DIR, '../modules/sec_mod/wordlists/common.txt')

        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist_content = [line.strip() for line in f.readlines()]

            enumerate_directories = DirectoryEnumeration(url, wordlist_content)
            results = enumerate_directories.enumerate_subdomain()
        else:
            results = ["Invalid wordlist selected or file not found."]

    return render_template('security/directory_enum.html', results=results)


