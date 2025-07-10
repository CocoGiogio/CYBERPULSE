from flask import Blueprint, render_template, request

llm_bp = Blueprint('llm', __name__, url_prefix='/llm')

@llm_bp.route('/remediation')
def remediation():
    return render_template('llm/remediation.html')

@llm_bp.route('/chatbot')
def chatbot():
    return render_template('llm/chatbot.html')
