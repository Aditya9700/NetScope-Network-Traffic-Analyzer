import os
from flask import Flask, render_template, jsonify
from config import Config
from api.routes import api_bp

def create_app():
    """
    Application factory to initialize Flask, configure routes, register blueprints,
    and hook error-handling mechanisms.
    """
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Mount REST API Blueprint
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Establish local folders
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOG_FOLDER'], exist_ok=True)
    
    # Set up directory gitkeeps
    for dirpath in [app.config['UPLOAD_FOLDER'], app.config['LOG_FOLDER']]:
        gitkeep = os.path.join(dirpath, '.gitkeep')
        if not os.path.exists(gitkeep):
            try:
                with open(gitkeep, 'w') as f:
                    pass
            except OSError:
                pass

    # UI Dashboard Views
    @app.route('/')
    def index():
        return render_template('index.html', active_page='home')
        
    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html', active_page='dashboard')
        
    @app.route('/upload')
    def upload():
        return render_template('upload.html', active_page='upload')
        
    @app.route('/statistics')
    def statistics():
        return render_template('statistics.html', active_page='statistics')
        
    @app.route('/about')
    def about():
        return render_template('about.html', active_page='about')
        
    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('index.html', active_page='home', error="Page not found"), 404
        
    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({'error': 'Security block: File upload size exceeds 16MB limit.'}), 413
        
    @app.errorhandler(500)
    def server_error(e):
        return jsonify({'error': 'An internal server error occurred.'}), 500
        
    return app

app = create_app()

if __name__ == '__main__':
    # Run server locally (debug mode enabled)
    app.run(host='127.0.0.1', port=5000, debug=True)
