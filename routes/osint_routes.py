from flask import Blueprint, render_template, request
from modules.osint_mod.google_dorking import GoogleDorking

osint_bp = Blueprint('osint', __name__, url_prefix='/osint')

@osint_bp.route('/google_dorking', methods=['GET', 'POST'])
def search():
    results = None
    if request.method == 'POST':
        platform = request.form.get('platform')
        username = request.form.get('username')
        google_dork = GoogleDorking(platform, username)
        results = google_dork.run_search()

    return render_template('osint/google_dorking.html', results=results)


