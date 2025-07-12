import socket
from flask import Blueprint, render_template, request

ports_scan_bp = Blueprint('ports_scan', __name__)

def scan_ports_with_services(host, start_port=1, end_port=65535, timeout=0.3):
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                open_ports.append({"port": port, "service": service})
    return open_ports

@ports_scan_bp.route('/port_scan', methods=['GET', 'POST'])
def port_scan():
    results = None
    host = '127.0.0.1'
    start_port = 1
    end_port = 65535
    timeout = 0.3

    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1')
        start_port = int(request.form.get('start_port', 1))
        end_port = int(request.form.get('end_port', 65535))
        timeout = float(request.form.get('timeout', 0.3))
        results = scan_ports_with_services(host, start_port, end_port, timeout)

    return render_template('security/port_scan.html', results=results, host=host,
                           start_port=start_port, end_port=end_port, timeout=timeout)
