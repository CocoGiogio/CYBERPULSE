from flask import Blueprint, render_template

security_bp = Blueprint('security', __name__, url_prefix='/security')

@security_bp.route('/net_scan')
def net_scan():
    return render_template('security/net_scan.html')

@security_bp.route('/directory_subdomain_enum')
def directory_enum():
    return render_template('security/directory_subdomain_enum.html')

@security_bp.route('/port_scan')
def port_scan():
    return render_template('security/port_scan.html')
