"""
Flask application factory.
"""
from flask import Flask
from flask_cors import CORS
from config import UPLOAD_FOLDER, MAX_CONTENT_LENGTH


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Enable CORS for frontend communication
    CORS(app)
    
    # Configure upload settings
    app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    
    # Register blueprints
    from app.routes import bp
    app.register_blueprint(bp)
    
    return app
