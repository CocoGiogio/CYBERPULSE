from flask import Flask, render_template, request, redirect, url_for

# Initialize the Flask app
app = Flask(__name__)

# Home page route
@app.route('/')
def home():
    return render_template('index.html')

# About page route
@app.route('/about')
def about():
    return render_template('about.html')

# Network Scanner page route
@app.route('/net_scan')
def net_scan():
    return render_template('net_scan.html')

# Port Scanner page route
@app.route('/port_scan')
def port_scan():
    return render_template('port_scan.html')

# Username search page route
@app.route('/username_search')
def username_search():
    return render_template('username_search.html')

# Google Dorking page route
@app.route('/google_dorking')
def google_dorking():
    return render_template('google_dorking.html')


# Remediation page route
@app.route('/remediation')
def remediation():
    return render_template('remediation.html')

# Chatbott page route
@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)