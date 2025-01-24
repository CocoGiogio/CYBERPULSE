from flask import Flask, render_template, request, redirect, url_for

# Initialize the Flask app
app = Flask(__name__)

# Home page route
@app.route('/')
def home():
    return render_template('index.html')

# Home page route
@app.route('/about')
def about():
    return render_template('about.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)