
# Enumeration Modules
from modules.sec_mod.directory_enum import DirectoryEnumeration
from modules.sec_mod.subdomain_enum import SubdomainEnumeration

# Networking Modules
from modules.sec_mod.net_scan import NetworkScanner
from modules.sec_mod.mitm import MITM
from modules.sec_mod.sniffing import Sniffing

# Libraries
from flask import Blueprint, render_template, request, jsonify
import os
import threading
import time

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

directory_progress_data = {"progress": 0, "results": []}

@security_bp.route('/directory_enum', methods=['GET', 'POST'])
def directory_enum():
    global directory_progress_data
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        wordlist = request.form.get('Wordlists')

        wordlist_path = None
        if wordlist == 'big.txt':
            wordlist_path = os.path.join(BASE_DIR, '../modules/sec_mod/wordlists/directories.txt')

        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist_content = [line.strip() for line in f.readlines()]

            directory_progress_data = {"progress": 0, "results": []}
            enum = DirectoryEnumeration(url, wordlist_content, directory_progress_data)

            def run_enum():
                directory_progress_data["results"] = enum.enumerate_directories()

            thread = threading.Thread(target=run_enum)
            thread.start()

            return render_template('security/directory_enum.html', started=True)

        else:
            results = ["[!] Invalid wordlist selected or file not found."]

    return render_template('security/directory_enum.html', results=results)

@security_bp.route('/directory_enum_progress')
def directory_enum_progress():
    return jsonify(progress=directory_progress_data["progress"], results=directory_progress_data["results"])


subdomain_progress_data = {"progress": 0, "results": []}

@security_bp.route('/subdomain_enum', methods=['GET', 'POST'])
def subdomain_enum():
    global subdomain_progress_data
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        wordlist = request.form.get('Wordlists')

        wordlist_path = None
        if wordlist == 'subdomain1':
            wordlist_path = os.path.join(BASE_DIR, '../modules/sec_mod/wordlists/subdomains.txt')

        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist_content = [line.strip() for line in f.readlines()]

            # Reset progress data
            subdomain_progress_data = {"progress": 0, "results": []}

            enum = SubdomainEnumeration(url, wordlist_content, subdomain_progress_data)

            def run_enum():
                subdomain_progress_data["results"] = enum.enumerate_subdomain()
                subdomain_progress_data["progress"] = 100  # Mark as complete after enumeration

            thread = threading.Thread(target=run_enum)
            thread.start()

            return render_template('security/subdomain_enum.html', started=True)

        else:
            results = ["[!] Invalid wordlist selected or file not found."]

    return render_template('security/subdomain_enum.html', results=results)


@security_bp.route('/subdomain_enum_progress')
def subdomain_enum_progress_route():
    global subdomain_progress_data
    return jsonify(progress=subdomain_progress_data["progress"], results=subdomain_progress_data["results"])
