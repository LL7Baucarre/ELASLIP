import hashlib
import secrets
from datetime import datetime
from functools import wraps

import bcrypt
from flask import request, jsonify, current_app, g
from flask_login import UserMixin, current_user

from app.services.elasticsearch_service import ElasticsearchService


class User(UserMixin):
    """User model for authentication."""
    
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.password_hash = user_data.get('password_hash')
        self.created_at = user_data.get('created_at')
        self.last_login = user_data.get('last_login')
        self.is_admin = user_data.get('is_admin', False)
        self.role = user_data.get('role', 'admin' if self.is_admin else 'viewer')
        self._permissions = None
    
    @property
    def permissions(self):
        """Get user permissions (cached)."""
        if self._permissions is None:
            from app.services.rbac_service import RBACService
            rbac = RBACService()
            self._permissions = rbac.get_user_permissions(self)
        return self._permissions
    
    def has_permission(self, permission):
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def has_any_permission(self, permissions):
        """Check if user has any of the specified permissions."""
        return any(p in self.permissions for p in permissions)
    
    def has_all_permissions(self, permissions):
        """Check if user has all of the specified permissions."""
        return all(p in self.permissions for p in permissions)
    
    def check_password(self, password):
        """Verify password against hash."""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    @staticmethod
    def hash_password(password):
        """Hash a password."""
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
    
    @classmethod
    def create(cls, username, email, password, is_admin=False, role=None):
        """Create a new user."""
        es = ElasticsearchService()
        
        # Check if user exists
        existing = es.search('users', {
            'query': {
                'bool': {
                    'should': [
                        {'term': {'username.keyword': username}},
                        {'term': {'email.keyword': email}}
                    ]
                }
            }
        })
        
        if existing['hits']['total']['value'] > 0:
            return None, "User already exists"
        
        # Determine role
        if role is None:
            role = 'admin' if is_admin else 'viewer'
        
        user_id = hashlib.sha256(username.encode()).hexdigest()[:16]
        user_data = {
            'id': user_id,
            'username': username,
            'email': email,
            'password_hash': cls.hash_password(password),
            'is_admin': is_admin,
            'role': role,
            'created_at': datetime.utcnow().isoformat(),
            'last_login': None
        }
        
        es.index('users', user_id, user_data)
        return cls(user_data), None
    
    @classmethod
    def get_by_id(cls, user_id):
        """Get user by ID."""
        es = ElasticsearchService()
        try:
            result = es.get('users', user_id)
            if result:
                return cls(result['_source'])
        except:
            pass
        return None
    
    @classmethod
    def get_by_username(cls, username):
        """Get user by username."""
        es = ElasticsearchService()
        result = es.search('users', {
            'query': {'term': {'username.keyword': username}}
        })
        
        if result['hits']['total']['value'] > 0:
            hit = result['hits']['hits'][0]
            user_data = hit['_source']
            user_data['id'] = hit['_id']
            return cls(user_data)
        return None
    
    def update_last_login(self):
        """Update last login timestamp."""
        es = ElasticsearchService()
        es.update('users', self.id, {
            'doc': {'last_login': datetime.utcnow().isoformat()}
        })
    
    @classmethod
    def get_all(cls):
        """Get all users."""
        es = ElasticsearchService()
        result = es.search('users', {
            'query': {'match_all': {}},
            'size': 1000
        })
        
        users = []
        for hit in result['hits']['hits']:
            user_data = hit['_source']
            user_data['id'] = hit['_id']
            users.append(cls(user_data))
        return users
    
    def update(self, **kwargs):
        """Update user fields."""
        es = ElasticsearchService()
        update_data = {}
        
        if 'email' in kwargs:
            update_data['email'] = kwargs['email']
            self.email = kwargs['email']
        if 'is_admin' in kwargs:
            update_data['is_admin'] = kwargs['is_admin']
            self.is_admin = kwargs['is_admin']
        if 'role' in kwargs:
            update_data['role'] = kwargs['role']
            self.role = kwargs['role']
            self._permissions = None  # Reset cached permissions
        if 'password' in kwargs:
            update_data['password_hash'] = self.hash_password(kwargs['password'])
            self.password_hash = update_data['password_hash']
        
        if update_data:
            es.update('users', self.id, {'doc': update_data})
    
    def delete(self):
        """Delete user."""
        es = ElasticsearchService()
        es.delete('users', self.id)
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'role': self.role,
            'permissions': self.permissions,
            'created_at': self.created_at,
            'last_login': self.last_login
        }


class APIKey:
    """API Key model."""
    
    def __init__(self, key_data):
        self.id = key_data.get('id')
        self.user_id = key_data.get('user_id')
        self.label = key_data.get('label')
        self.key_hash = key_data.get('key_hash')
        self.key_prefix = key_data.get('key_prefix')
        self.created_at = key_data.get('created_at')
        self.last_used = key_data.get('last_used')
    
    @staticmethod
    def generate_key():
        """Generate a new API key."""
        prefix = current_app.config.get('API_KEY_PREFIX', 'ioc_')
        key = prefix + secrets.token_hex(32)
        return key
    
    @staticmethod
    def hash_key(key):
        """Hash an API key."""
        return hashlib.sha256(key.encode()).hexdigest()
    
    @classmethod
    def create(cls, user_id, label):
        """Create a new API key."""
        es = ElasticsearchService()
        
        key = cls.generate_key()
        key_id = secrets.token_hex(8)
        prefix = current_app.config.get('API_KEY_PREFIX', 'ioc_')
        
        key_data = {
            'id': key_id,
            'user_id': user_id,
            'label': label,
            'key_hash': cls.hash_key(key),
            'key_prefix': key[:len(prefix) + 8],  # Store prefix for display
            'created_at': datetime.utcnow().isoformat(),
            'last_used': None
        }
        
        es.index('api_keys', key_id, key_data)
        
        # Return the key only once (not stored in plain text)
        return key, cls(key_data)
    
    @classmethod
    def get_by_key(cls, key):
        """Get API key by the key value."""
        es = ElasticsearchService()
        key_hash = cls.hash_key(key)
        
        result = es.search('api_keys', {
            'query': {'term': {'key_hash': key_hash}}
        })
        
        if result['hits']['total']['value'] > 0:
            hit = result['hits']['hits'][0]
            key_data = hit['_source']
            key_data['id'] = hit['_id']
            return cls(key_data)
        return None
    
    @classmethod
    def get_by_user(cls, user_id):
        """Get all API keys for a user."""
        es = ElasticsearchService()
        result = es.search('api_keys', {
            'query': {'term': {'user_id': user_id}},
            'size': 100
        })
        
        keys = []
        for hit in result['hits']['hits']:
            key_data = hit['_source']
            key_data['id'] = hit['_id']
            keys.append(cls(key_data))
        return keys
    
    @classmethod
    def revoke(cls, key_id, user_id):
        """Revoke an API key."""
        es = ElasticsearchService()
        
        # Verify ownership
        try:
            result = es.get('api_keys', key_id)
            if result and result['_source']['user_id'] == user_id:
                es.delete('api_keys', key_id)
                return True
        except:
            pass
        return False
    
    def update_last_used(self):
        """Update last used timestamp."""
        es = ElasticsearchService()
        es.update('api_keys', self.id, {
            'doc': {'last_used': datetime.utcnow().isoformat()}
        })
    
    def to_dict(self):
        """Convert to dictionary (without hash)."""
        return {
            'id': self.id,
            'label': self.label,
            'key_prefix': self.key_prefix,
            'created_at': self.created_at,
            'last_used': self.last_used
        }


def api_key_required(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get(current_app.config.get('API_KEY_HEADER', 'X-API-Key'))
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        key_obj = APIKey.get_by_key(api_key)
        if not key_obj:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Get user
        user = User.get_by_id(key_obj.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        # Update last used
        key_obj.update_last_used()
        
        # Set user in request context
        g.current_user = user
        g.api_key = key_obj
        
        return f(*args, **kwargs)
    return decorated_function


def login_or_api_key_required(f):
    """Decorator to require either session login or API key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key first
        api_key = request.headers.get(current_app.config.get('API_KEY_HEADER', 'X-API-Key'))
        
        if api_key:
            key_obj = APIKey.get_by_key(api_key)
            if key_obj:
                user = User.get_by_id(key_obj.user_id)
                if user:
                    key_obj.update_last_used()
                    g.current_user = user
                    g.api_key = key_obj
                    return f(*args, **kwargs)
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Check for session login
        if current_user.is_authenticated:
            g.current_user = current_user
            g.api_key = None
            return f(*args, **kwargs)
        
        return jsonify({'error': 'Authentication required'}), 401
    
    return decorated_function


def permission_required(*permissions):
    """Decorator to require specific permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None) or current_user
            
            if not user or not user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Check if user has any of the required permissions
            if not user.has_any_permission(permissions):
                return jsonify({
                    'error': 'Permission denied',
                    'required_permissions': list(permissions)
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required_all(*permissions):
    """Decorator to require ALL specified permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None) or current_user
            
            if not user or not user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Check if user has all of the required permissions
            if not user.has_all_permissions(permissions):
                return jsonify({
                    'error': 'Permission denied',
                    'required_permissions': list(permissions)
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
