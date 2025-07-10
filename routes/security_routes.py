from flask import Blueprint, render_template, request
from modules.sec_mod.directory_enum import DirectoryEnumeration
from modules.sec_mod.net_scan import NetworkScanner

import os

# Define BASE_DIR at the top
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

security_bp = Blueprint('security', __name__, url_prefix='/security')

# Network Scan
@security_bp.route('/net_scan', methods=['GET', 'POST'])
def net_scan():
    results = None
    if request.method == 'POST':
        IP = request.form.get('IP')
        if IP:
            scanner = NetworkScanner(IP)
            results = scanner.scan()
    return render_template('security/net_scan.html', results=results)

# Port Scanner
@security_bp.route('/port_scan')
def port_scan():
    return render_template('security/port_scan.html')


# Port Scanner
@security_bp.route('/mitm_sniffing')
def mitm_sniffing():
    return render_template('security/mitm_sniffing.html')

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


