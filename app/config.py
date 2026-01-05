import os
from dotenv import load_dotenv

load_dotenv()

# Application Version
__version__ = "1.2.1"


def env_bool(name: str, default: bool = False) -> bool:
    """
    Read a boolean environment variable in a consistent way.

    Accepted truthy values (case-insensitive): "1", "true", "t", "yes", "y", "on"
    Accepted falsy values (case-insensitive):  "0", "false", "f", "no", "n", "off"

    Any other value falls back to the provided default.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


class Config:
    """Application configuration."""
    
    # Application Version
    APP_VERSION = os.getenv('APP_VERSION', __version__)
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'app.log')
    
    # Site Configuration
    SITE_NAME = os.getenv('SITE_NAME', 'IOC Manager')
    SITE_TITLE = os.getenv('SITE_TITLE', 'IOC Manager')
    
    # Elasticsearch
    ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
    ELASTICSEARCH_USER = os.getenv('ELASTICSEARCH_USER', 'elastic')
    ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', 'elastic123')
    
    
    # Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    SESSION_REDIS_DB = int(os.getenv('SESSION_REDIS_DB', '2'))
    
    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    
    # Default Admin
    DEFAULT_ADMIN_USER = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    # API Keys
    API_KEY_PREFIX = 'ioc_'
    API_KEY_HEADER = 'X-API-Key'
    
    # Session
    SESSION_TYPE = 'redis'
    SESSION_REDIS = None  # Will be set in __init__.py
    SESSION_KEY_PREFIX = 'session:'
    SESSION_USE_SIGNER = True  # Sign session cookies
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    SESSION_COOKIE_SAMESITE = 'Lax'  # Allow cookies in AJAX requests
    SESSION_COOKIE_SECURE = env_bool('SESSION_COOKIE_SECURE', default=True)
    SESSION_COOKIE_HTTPONLY = True
    
    # Enrichment cache TTL (seconds)
    ENRICHMENT_CACHE_TTL = 3600  # 1 hour
    
    # Webhook settings
    WEBHOOK_MAX_RETRIES = 3
    WEBHOOK_RETRY_DELAY = 5  # seconds
    
    # Upload settings
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', '100')) * 1024 * 1024  # Max file size in MB
    MAX_CONTENT_LENGTH = MAX_FILE_SIZE
    
    # LLM Configuration (Ollama or OpenAI-compatible)
    # For Docker: http://ollama:11434 (service name), for local: http://localhost:11434
    LLM_URL = os.getenv('LLM_URL', 'http://ollama:11434')
    LLM_MODEL = os.getenv('LLM_MODEL', 'mistral')
    LLM_API_KEY = os.getenv('LLM_API_KEY', '')
    LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'auto')  # 'auto', 'ollama', or 'openai'
    LLM_ENABLED = env_bool('LLM_ENABLED', default=False)
    LLM_GENERATION_LANGUAGE = os.getenv('LLM_GENERATION_LANGUAGE', 'en')
    
    # Public Submissions Configuration
    PUBLIC_SEARCH_ENABLED = env_bool('PUBLIC_SEARCH_ENABLED', default=True)
    PUBLIC_SUBMISSIONS_SUBMIT_ENABLED = env_bool('PUBLIC_SUBMISSIONS_SUBMIT_ENABLED', default=True)
    PUBLIC_SUBMISSIONS_MAX_RESULTS = int(os.getenv('PUBLIC_SUBMISSIONS_MAX_RESULTS', '10'))
    PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS = env_bool('PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS', default=True)
    
    # OAuth2/OIDC Configuration
    OAUTH_ENABLED = env_bool('OAUTH_ENABLED', default=False)
    OAUTH_AUTO_CREATE_USER = env_bool('OAUTH_AUTO_CREATE_USER', default=True)
    OAUTH_AUTO_LINK_BY_EMAIL = env_bool('OAUTH_AUTO_LINK_BY_EMAIL', default=False)
    OAUTH_DEFAULT_ROLE = os.getenv('OAUTH_DEFAULT_ROLE', 'viewer')
    
    # OAuth Provider: Google
    OAUTH_GOOGLE_ENABLED = env_bool('OAUTH_GOOGLE_ENABLED', default=False)
    OAUTH_GOOGLE_CLIENT_ID = os.getenv('OAUTH_GOOGLE_CLIENT_ID', '')
    OAUTH_GOOGLE_CLIENT_SECRET = os.getenv('OAUTH_GOOGLE_CLIENT_SECRET', '')
    OAUTH_GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    
    # OAuth Provider: GitHub
    OAUTH_GITHUB_ENABLED = env_bool('OAUTH_GITHUB_ENABLED', default=False)
    OAUTH_GITHUB_CLIENT_ID = os.getenv('OAUTH_GITHUB_CLIENT_ID', '')
    OAUTH_GITHUB_CLIENT_SECRET = os.getenv('OAUTH_GITHUB_CLIENT_SECRET', '')
    
    # OAuth Provider: Generic OIDC (e.g., Keycloak, Auth0)
    OAUTH_OIDC_ENABLED = env_bool('OAUTH_OIDC_ENABLED', default=False)
    OAUTH_OIDC_CLIENT_ID = os.getenv('OAUTH_OIDC_CLIENT_ID', '')
    OAUTH_OIDC_CLIENT_SECRET = os.getenv('OAUTH_OIDC_CLIENT_SECRET', '')
    OAUTH_OIDC_DISCOVERY_URL = os.getenv('OAUTH_OIDC_DISCOVERY_URL', '')
    OAUTH_OIDC_PROVIDER_NAME = os.getenv('OAUTH_OIDC_PROVIDER_NAME', 'OIDC')
    
    # OAuth Token Encryption Key (must be 32 url-safe base64-encoded bytes)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    OAUTH_ENCRYPTION_KEY = os.getenv('OAUTH_ENCRYPTION_KEY', None)
    
    # Shodan API Configuration
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    SHODAN_ENABLED = env_bool('SHODAN_ENABLED', default=False) if os.getenv('SHODAN_API_KEY') else False


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
