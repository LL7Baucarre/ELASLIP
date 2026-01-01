"""Initialize Elasticsearch indices."""

import os
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError

from app.elasticsearch.mappings import INDICES
import logging
logger = logging.getLogger(__name__)


def get_elasticsearch_client():
    """Get Elasticsearch client."""
    es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
    es_user = os.getenv('ELASTICSEARCH_USER', 'elastic')
    es_password = os.getenv('ELASTICSEARCH_PASSWORD', 'elastic123')
    
    # Construct URL with credentials if not already included
    if es_user and es_password and 'http://' in es_url and '@' not in es_url:
        es_url = es_url.replace('http://', f'http://{es_user}:{es_password}@')
    
    return Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False)


def init_elasticsearch():
    """Initialize all Elasticsearch indices."""
    es = get_elasticsearch_client()
    
    # Wait for Elasticsearch to be ready
    if not es.ping():
        logger.warning("Elasticsearch is not available")
        return False
    
    logger.info("Initializing Elasticsearch indices...")
    
    for index_name, mapping in INDICES.items():
        try:
            if not es.indices.exists(index=index_name):
                es.indices.create(index=index_name, body=mapping)
                logger.info("Created index: %s", index_name)
            else:
                logger.info("Index already exists: %s", index_name)
        except RequestError as e:
            logger.exception("Error creating index %s: %s", index_name, e)
    
    # Create default admin user if it doesn't exist
    create_default_admin(es)
    
    # Create default roles if they don't exist
    create_default_roles(es)
    
    logger.info("Elasticsearch initialization complete")
    return True


def create_default_roles(es):
    """Create default roles if they don't exist."""
    from app.services.rbac_service import RBACService
    
    try:
        rbac = RBACService()
        rbac.init_default_roles()
        logger.info("Default roles initialized")
    except Exception as e:
        logger.exception("Could not initialize default roles: %s", e)


def create_default_admin(es):
    """Create default admin user if it doesn't exist."""
    from app.auth import User
    
    admin_username = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    # Check if admin exists
    result = es.search(
        index='elaslip_users',
        body={
            'query': {'term': {'username.keyword': admin_username}}
        },
        ignore=[404]
    )
    
    if result.get('hits', {}).get('total', {}).get('value', 0) == 0:
        # Create admin user
        import hashlib
        import bcrypt
        from datetime import datetime
        
        user_id = hashlib.sha256(admin_username.encode()).hexdigest()[:16]
        password_hash = bcrypt.hashpw(
            admin_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
        
        user_data = {
            'id': user_id,
            'username': admin_username,
            'email': f'{admin_username}@localhost',
            'password_hash': password_hash,
            'is_admin': True,
            'role_id': 'admin',
            'created_at': datetime.utcnow().isoformat(),
            'last_login': None
        }
        
        es.index(index='elaslip_users', id=user_id, document=user_data)
        logger.info("Created default admin user: %s", admin_username)
    else:
        logger.info("Admin user already exists: %s", admin_username)
