from .home_routes import home_bp
from .osint_routes import osint_bp
from .security_routes import security_bp
from .llm_routes import llm_bp

def register_routes(app):
    app.register_blueprint(home_bp)
    app.register_blueprint(osint_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(llm_bp)
