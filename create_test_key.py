#!/usr/bin/env python3
"""Create a test API key."""

import sys
sys.path.insert(0, '/app')

from app.services.elasticsearch_service import ElasticsearchService
import uuid
import hashlib
from datetime import datetime

def create_test_user_and_key():
    """Create a test user and API key."""
    
    es = ElasticsearchService()
    
    # Create test user
    user_id = str(uuid.uuid4())
    user_data = {
        'id': user_id,
        'username': 'testuser',
        'email': 'test@example.com',
        'password_hash': 'dummy_hash',
        'is_active': True,
        'created_at': datetime.utcnow().isoformat()
    }
    
    es.index('users', user_id, user_data)
    
    print(f"Created test user: {user_id}")
    
    # Create API key
    key_value = f'ioc_{uuid.uuid4().hex}'
    key_hash = hashlib.sha256(key_value.encode()).hexdigest()
    
    key_data = {
        'user_id': user_id,
        'name': 'Test API Key',
        'key_hash': key_hash,
        'is_active': True,
        'created_at': datetime.utcnow().isoformat(),
        'last_used': None
    }
    
    key_id = str(uuid.uuid4())
    es.index('api_keys', key_id, key_data)
    
    print(f"Created API key (hashed): {key_hash}")
    print(f"Use this key for testing: {key_value}")
    
    return key_value

if __name__ == "__main__":
    api_key = create_test_user_and_key()
    print(f"\nAPI Key for testing:")
    print(api_key)
