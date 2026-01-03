import os
from flask import Flask
from flask_login import LoginManager, current_user
from flask_jwt_extended import JWTManager
from flask_session import Session
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
    
    # Ensure MAX_CONTENT_LENGTH is set (for file uploads)
    if 'MAX_CONTENT_LENGTH' not in app.config or app.config['MAX_CONTENT_LENGTH'] is None:
        app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB default
    
    # Initialize logging from central config
    from app.logging_config import init_logging
    init_logging(app.config)
    
    # Validate OAuth encryption key if OAuth is enabled
    if app.config.get('OAUTH_ENABLED', False):
        providers_enabled = [
            app.config.get('OAUTH_GOOGLE_ENABLED', False),
            app.config.get('OAUTH_GITHUB_ENABLED', False),
            app.config.get('OAUTH_OIDC_ENABLED', False)
        ]
        
        if any(providers_enabled):
            encryption_key = app.config.get('OAUTH_ENCRYPTION_KEY')
            if not encryption_key:
                raise ValueError(
                    'OAUTH_ENCRYPTION_KEY is required when OAuth providers are enabled. '
                    'Generate one with: python -c "from cryptography.fernet import Fernet; '
                    'print(Fernet.generate_key().decode())"'
                )
    
    # Initialize extensions
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    jwt.init_app(app)
    
    # Initialize Flasgger for Swagger UI with authentication protection
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/apidocs/"
    }
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": app.config.get('SITE_TITLE', 'IOC Manager') + " API",
            "description": "Comprehensive API for managing Indicators of Compromise (IOCs), investigations, incidents, checklists, and security operations with role-based access control.",
            "version": "1.0.0",
            "contact": {
                "name": "ELASLIP Support",
                "url": "https://github.com/LL7Baucarre/ELASLIP"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "basePath": "/api",
        "schemes": ["http", "https"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "securityDefinitions": {
            "api_key": {
                "type": "apiKey",
                "name": "X-API-Key",
                "in": "header",
                "description": "API Key for authentication. Generate one in API Keys settings."
            },
            "session": {
                "type": "basic",
                "description": "Session-based authentication via login"
            }
        },
        "security": [
            {"api_key": []}
        ],
        "tags": [
            {
                "name": "IOCs",
                "description": "Indicator of Compromise management"
            },
            {
                "name": "Search",
                "description": "IOC search and filtering"
            },
            {
                "name": "Relations",
                "description": "IOC relationship management"
            },
            {
                "name": "Cases",
                "description": "Investigation case management"
            },
            {
                "name": "Incidents",
                "description": "Security incident management"
            },
            {
                "name": "Checklists",
                "description": "Security checklist management"
            },
            {
                "name": "Reports",
                "description": "Report generation with LLM support"
            },
            {
                "name": "Tools",
                "description": "Security tools integration (nmap, ping, whois, etc.)"
            },
            {
                "name": "Webhooks",
                "description": "Event webhooks and integrations"
            },
            {
                "name": "API Keys",
                "description": "API key management"
            },
            {
                "name": "Submissions",
                "description": "Public IOC submissions"
            },
            {
                "name": "Notifications",
                "description": "User notifications"
            },
            {
                "name": "RBAC",
                "description": "Role-based access control"
            },
            {
                "name": "FinOps",
                "description": "LLM token usage tracking"
            }
        ]
    }
    
    swagger = Flasgger(
        app,
        config=swagger_config,
        template=swagger_template
    )
    
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
        """Inject configuration and utilities into all templates."""
        from flask_login import current_user
        from app.services.rbac_service import RBACService
        
        def has_permission(permission):
            """Check if current user has a specific permission."""
            if not current_user.is_authenticated:
                return False
            if current_user.is_admin:
                return True
            rbac = RBACService()
            return rbac.user_has_permission(current_user, permission)
        
        def has_any_permission(*permissions):
            """Check if current user has any of the given permissions."""
            if not current_user.is_authenticated:
                return False
            if current_user.is_admin:
                return True
            rbac = RBACService()
            return rbac.user_has_any_permission(current_user, list(permissions))
        
        return {
            'SITE_NAME': app.config.get('SITE_NAME', 'IOC Manager'),
            'SITE_TITLE': app.config.get('SITE_TITLE', 'IOC Manager'),
            'has_permission': has_permission,
            'has_any_permission': has_any_permission,
            'llm_enabled': os.getenv('LLM_ENABLED', 'false').lower() == 'true'
        }
    
    # Initialize Redis
    global redis_client
    redis_client = Redis.from_url(app.config['REDIS_URL'])
    
    # Initialize Flask-Session with Redis
    # Use configurable DB for sessions to avoid conflicts with Celery (DB 1) and app data (DB 0)
    # Priority: SESSION_REDIS_DB env var > DB index from REDIS_URL > default 2
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(app.config['REDIS_URL'])
    
    # Extract DB index from REDIS_URL path (e.g., /5 from redis://host:6379/5)
    db_from_url = None
    if parsed.path and parsed.path != '/':
        try:
            db_from_url = int(parsed.path.lstrip('/'))
        except (ValueError, AttributeError):
            pass
    
    # Determine session DB: explicit config > URL-derived > default 2
    session_db = app.config.get('SESSION_REDIS_DB')
    if session_db is None:
        session_db = db_from_url if db_from_url is not None else 2
    
    session_redis_url = urlunparse((parsed.scheme, parsed.netloc, f'/{session_db}', parsed.params, parsed.query, parsed.fragment))
    session_redis = Redis.from_url(session_redis_url, decode_responses=False)
    app.config['SESSION_REDIS'] = session_redis
    Session(app)
    
    # Initialize Celery
    global celery
    celery = create_celery_app(app)
    
    # Import task modules so Celery can discover them
    from app.tasks import scan_tasks, webhook_tasks, import_tasks, expiration_tasks, report_tasks
    
    # Initialize Elasticsearch indices
    from app.elasticsearch.init_indices import init_elasticsearch
    with app.app_context():
        init_elasticsearch()
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.oauth import oauth_bp
    from app.routes.ioc import ioc_bp
    from app.routes.ioc_relations import ioc_relations_bp
    from app.routes.search import search_bp
    from app.routes.import_routes import import_bp
    from app.routes.api_config import api_config_bp
    from app.routes.webhook import webhook_bp
    from app.routes.main import main_bp
    from app.routes.api_keys import api_keys_bp
    from app.routes.tools import tools_bp
    from app.routes.images import images_bp
    from app.routes.audit import audit_bp
    from app.routes.cases import bp as cases_bp
    from app.routes.reports import bp as reports_bp
    from app.routes.checklists import bp as checklists_bp
    from app.routes.checklist_templates import bp as checklist_templates_bp
    from app.routes.rbac import rbac_bp
    from app.routes.finops import finops_bp
    from app.routes.submissions import submissions_bp, public_bp
    from app.routes.notifications import bp as notifications_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(oauth_bp, url_prefix='/oauth')
    app.register_blueprint(ioc_bp, url_prefix='/api/ioc')
    app.register_blueprint(ioc_relations_bp, url_prefix='/api')
    app.register_blueprint(search_bp, url_prefix='/api/search')
    app.register_blueprint(import_bp, url_prefix='/api/import')
    app.register_blueprint(api_config_bp, url_prefix='/api/external-apis')
    app.register_blueprint(webhook_bp, url_prefix='/api/webhooks')
    app.register_blueprint(api_keys_bp, url_prefix='/api/api-keys')
    app.register_blueprint(tools_bp, url_prefix='/api/tools')
    app.register_blueprint(images_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(checklists_bp)
    app.register_blueprint(checklist_templates_bp)
    app.register_blueprint(rbac_bp, url_prefix='/api/rbac')
    app.register_blueprint(finops_bp)
    app.register_blueprint(submissions_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(notifications_bp)

    # Make app version available to all templates
    @app.context_processor
    def inject_app_version():
        return {
            'APP_VERSION': app.config.get('APP_VERSION', '1.0.0')
        }
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {'status': 'healthy'}, 200
    
    return app


# Create celery app for worker
celery_app = create_celery_app()
# Import tasks so they're registered with the worker
from app.tasks import scan_tasks, webhook_tasks, import_tasks, expiration_tasks, report_tasks