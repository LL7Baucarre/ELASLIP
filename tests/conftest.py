"""Pytest configuration and fixtures."""

import os
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.auth import User


@pytest.fixture
def app():
    """Create and configure a test app."""
    os.environ['TESTING'] = 'True'
    os.environ['FLASK_ENV'] = 'testing'
    
    # Configure Elasticsearch for testing (Docker)
    os.environ['ELASTICSEARCH_URL'] = os.environ.get('ELASTICSEARCH_URL', 'http://localhost:9200')
    os.environ['ELASTICSEARCH_USER'] = os.environ.get('ELASTICSEARCH_USER', 'elastic')
    os.environ['ELASTICSEARCH_PASSWORD'] = os.environ.get('ELASTICSEARCH_PASSWORD', 'elastic123')
    os.environ['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    os.environ['DEFAULT_ADMIN_USER'] = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
    os.environ['DEFAULT_ADMIN_PASSWORD'] = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    app = create_app()
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SERVER_NAME'] = None  # Disable host matching for tests
    
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def app_context(app):
    """Create an application context."""
    with app.app_context():
        yield app


@pytest.fixture
def test_user(app_context):
    """Get or create the default test user (admin)."""
    try:
        user = User.get_by_username('admin')
        if not user:
            result = User.create(
                username='admin',
                email='admin@test.local',
                password='admin123',
                is_admin=True
            )
            # User.create returns (user, error) tuple
            user = result[0] if isinstance(result, tuple) else result
        return user
    except Exception as e:
        # Fallback to mock if user creation fails
        user = Mock(spec=User)
        user.id = 'admin-id'
        user.username = 'admin'
        user.email = 'admin@test.local'
        user.is_authenticated = True
        user.is_active = True
        user.is_admin = True
        user.is_anonymous = False
        user.get_id = Mock(return_value='admin-id')
        user.to_dict = Mock(return_value={
            'id': 'admin-id',
            'username': 'admin',
            'email': 'admin@test.local'
        })
        user.check_password = Mock(return_value=True)
        user.update_last_login = Mock()
        return user


@pytest.fixture
def mock_user():
    """Create a mock user."""
    user = Mock(spec=User)
    user.id = 'test-user-id'
    user.username = 'testuser'
    user.email = 'test@example.com'
    user.is_authenticated = True
    user.is_active = True
    user.is_anonymous = False
    user.is_admin = False
    user.get_id = Mock(return_value='test-user-id')
    user.to_dict = Mock(return_value={
        'id': 'test-user-id',
        'username': 'testuser',
        'email': 'test@example.com'
    })
    user.check_password = Mock(return_value=True)
    user.update_last_login = Mock()
    return user


@pytest.fixture
def authenticated_client(client, test_user, app):
    """Create an authenticated test client with real user."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_user.id)
        sess['_fresh'] = True
    yield client


@pytest.fixture
def mock_ioc_service():
    """Create a mock IOC service."""
    service = Mock()
    service.create_ioc = Mock()
    service.get_ioc = Mock()
    service.get_all_iocs = Mock(return_value=[])
    service.update_ioc = Mock()
    service.delete_ioc = Mock()
    service.search_iocs = Mock(return_value=[])
    return service


@pytest.fixture
def mock_elasticsearch():
    """Create a mock Elasticsearch client."""
    client = MagicMock()
    return client


@pytest.fixture
def sample_ioc_data():
    """Sample IOC data for testing."""
    return {
        'type': 'ipv4',
        'value': '192.168.1.1',
        'labels': ['malicious', 'c2'],
        'source': 'test-source',
        'name': 'Test IOC'
    }


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'SecurePassword123!'
    }
