import os
from flask import Flask
from flask_login import LoginManager, current_user
from flask_jwt_extended import JWTManager
from celery import Celery
from redis import Redis
from flasgger import Flasgger

from app.config import config

login_manager = LoginManager()
jwt = JWTManager()
celery = Celery()
redis_client = None


def create_celery_app(app=None):
    """Create Celery application."""
    celery = Celery(
        app.import_name if app else __name__,
        broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
        backend=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    )
    
    if app:
        celery.conf.update(app.config)
        
        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)
        
        celery.Task = ContextTask
    
    return celery


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')
    
    # Load configuration
    app.config.from_object(config.get(config_name, config['default']))
    
    # Initialize extensions
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    jwt.init_app(app)
    
    # Initialize Flasgger for Swagger UI with authentication protection
    swagger = Flasgger(app)
    
    @app.before_request
    def protect_swagger():
        """Require authentication for Swagger UI."""
        from flask import request
        if request.path.startswith('/apidocs') or request.path.startswith('/flasgger'):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
    
    # Pass configuration to templates
    @app.context_processor
    def inject_config():
        """Inject configuration into all templates."""
        return {
            'SITE_NAME': app.config.get('SITE_NAME', 'IOC Manager'),
            'SITE_TITLE': app.config.get('SITE_TITLE', 'IOC Manager')
        }
    
    # Initialize Redis
    global redis_client
    redis_client = Redis.from_url(app.config['REDIS_URL'])
    
    # Initialize Celery
    global celery
    celery = create_celery_app(app)
    
    # Import task modules so Celery can discover them
    from app.tasks import scan_tasks, webhook_tasks, import_tasks, expiration_tasks
    
    # Initialize Elasticsearch indices
    from app.elasticsearch.init_indices import init_elasticsearch
    with app.app_context():
        init_elasticsearch()
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.ioc import ioc_bp
    from app.routes.ioc_relations import ioc_relations_bp
    from app.routes.search import search_bp
    from app.routes.import_routes import import_bp
    from app.routes.api_config import api_config_bp
    from app.routes.webhook import webhook_bp
    from app.routes.main import main_bp
    from app.routes.api_keys import api_keys_bp
    from app.routes.tools import tools_bp
    from app.routes.audit import audit_bp
    from app.routes.cases import bp as cases_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(ioc_bp, url_prefix='/api/ioc')
    app.register_blueprint(ioc_relations_bp, url_prefix='/api')
    app.register_blueprint(search_bp, url_prefix='/api/search')
    app.register_blueprint(import_bp, url_prefix='/api/import')
    app.register_blueprint(api_config_bp, url_prefix='/api/external-apis')
    app.register_blueprint(webhook_bp, url_prefix='/api/webhooks')
    app.register_blueprint(api_keys_bp, url_prefix='/api/api-keys')
    app.register_blueprint(tools_bp, url_prefix='/api/tools')
    app.register_blueprint(audit_bp)
    app.register_blueprint(cases_bp)

    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {'status': 'healthy'}, 200
    
    return app


# Create celery app for worker
celery_app = create_celery_app()
# Import tasks so they're registered with the worker
from app.tasks import scan_tasks, webhook_tasks, import_tasks, expiration_tasks