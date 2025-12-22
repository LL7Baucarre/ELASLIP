import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    
    # Site Configuration
    SITE_NAME = os.getenv('SITE_NAME', 'IOC Manager')
    SITE_TITLE = os.getenv('SITE_TITLE', 'IOC Manager')
    
    # Elasticsearch
    ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
    ELASTICSEARCH_USER = os.getenv('ELASTICSEARCH_USER', 'elastic')
    ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', 'elastic123')
    
    # Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
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
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Enrichment cache TTL (seconds)
    ENRICHMENT_CACHE_TTL = 3600  # 1 hour
    
    # Webhook settings
    WEBHOOK_MAX_RETRIES = 3
    WEBHOOK_RETRY_DELAY = 5  # seconds
    
    # Upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
