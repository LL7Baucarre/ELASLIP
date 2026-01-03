"""Tests for OAuth authentication functionality."""

import pytest
import secrets
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from app import create_app
from app.services.oauth_service import OAuthService
from app.services.oauth_account_service import OAuthAccountService
from app.services.oauth_providers.google import GoogleOAuthProvider
from app.services.oauth_providers.github import GitHubOAuthProvider


@pytest.fixture
def app():
    """Create test Flask app."""
    app = create_app('testing')
    app.config['TESTING'] = True
    app.config['OAUTH_ENABLED'] = True
    app.config['OAUTH_GOOGLE_ENABLED'] = True
    app.config['OAUTH_GOOGLE_CLIENT_ID'] = 'test_google_client_id'
    app.config['OAUTH_GOOGLE_CLIENT_SECRET'] = 'test_google_client_secret'
    app.config['OAUTH_GITHUB_ENABLED'] = True
    app.config['OAUTH_GITHUB_CLIENT_ID'] = 'test_github_client_id'
    app.config['OAUTH_GITHUB_CLIENT_SECRET'] = 'test_github_client_secret'
    app.config['OAUTH_ENCRYPTION_KEY'] = 'test_encryption_key_32_bytes_long!'
    
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestGoogleOAuthProvider:
    """Test Google OAuth provider."""
    
    def test_provider_initialization(self, app):
        """Test provider can be initialized with config."""
        provider = GoogleOAuthProvider()
        assert provider.PROVIDER_NAME == 'google'
        assert provider.client_id == 'test_google_client_id'
        assert provider.client_secret == 'test_google_client_secret'
    
    def test_normalize_user_info(self, app):
        """Test normalization of Google user profile."""
        provider = GoogleOAuthProvider()
        
        raw_profile = {
            'sub': '1234567890',
            'email': 'test@example.com',
            'email_verified': True,
            'name': 'Test User',
            'given_name': 'Test',
            'family_name': 'User',
            'picture': 'https://example.com/photo.jpg',
            'locale': 'en'
        }
        
        normalized = provider._normalize_user_info(raw_profile)
        
        assert normalized['provider_user_id'] == '1234567890'
        assert normalized['email'] == 'test@example.com'
        assert normalized['email_verified'] is True
        assert normalized['name'] == 'Test User'
        assert normalized['given_name'] == 'Test'
        assert normalized['family_name'] == 'User'
    
    def test_generate_authorization_url(self, app):
        """Test authorization URL generation with PKCE."""
        provider = GoogleOAuthProvider()
        
        state = 'test_state_12345'
        redirect_uri = 'http://localhost/oauth/callback/google'
        
        auth_url, code_verifier = provider.get_authorization_url(state, redirect_uri)
        
        # Check URL contains required parameters
        assert 'accounts.google.com' in auth_url
        assert 'client_id=test_google_client_id' in auth_url
        assert 'redirect_uri=' in auth_url
        assert 'state=test_state_12345' in auth_url
        assert 'code_challenge=' in auth_url
        assert 'code_challenge_method=S256' in auth_url
        
        # Check code verifier is returned
        assert code_verifier is not None
        assert len(code_verifier) > 0


class TestGitHubOAuthProvider:
    """Test GitHub OAuth provider."""
    
    def test_provider_initialization(self, app):
        """Test provider can be initialized with config."""
        provider = GitHubOAuthProvider()
        assert provider.PROVIDER_NAME == 'github'
        assert provider.client_id == 'test_github_client_id'
    
    def test_normalize_user_info(self, app):
        """Test normalization of GitHub user profile."""
        provider = GitHubOAuthProvider()
        
        raw_profile = {
            'id': 123456,
            'login': 'testuser',
            'email': 'test@example.com',
            'name': 'Test User',
            'avatar_url': 'https://avatars.githubusercontent.com/u/123456',
            'bio': 'Developer',
            'company': 'Test Co',
            'location': 'Test City'
        }
        
        normalized = provider._normalize_user_info(raw_profile)
        
        assert normalized['provider_user_id'] == '123456'
        assert normalized['email'] == 'test@example.com'
        assert normalized['username'] == 'testuser'
        assert normalized['name'] == 'Test User'
    
    def test_normalize_user_info_with_null_email(self, app):
        """Test normalization when email is private."""
        provider = GitHubOAuthProvider()
        
        raw_profile = {
            'id': 123456,
            'login': 'testuser',
            'email': None,  # Private email
            'name': 'Test User',
            'avatar_url': 'https://avatars.githubusercontent.com/u/123456'
        }
        
        normalized = provider._normalize_user_info(raw_profile)
        
        # Should generate a noreply email
        assert '@users.noreply.github.com' in normalized['email']
        assert 'testuser' in normalized['email']


class TestOAuthAccountService:
    """Test OAuth account service."""
    
    @patch('app.services.oauth_account_service.ElasticsearchService')
    @patch('app.services.oauth_account_service.EncryptionService')
    def test_create_oauth_account(self, mock_encryption, mock_es, app):
        """Test creating OAuth account linkage."""
        # Setup mocks
        mock_encryption_instance = Mock()
        mock_encryption_instance.encrypt.side_effect = lambda x: f'encrypted_{x}'
        mock_encryption.return_value = mock_encryption_instance
        
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        
        # Create service
        service = OAuthAccountService()
        
        # Create OAuth account
        account = service.create_oauth_account(
            user_id='user123',
            provider='google',
            provider_user_id='google123',
            email='test@example.com',
            access_token='access_token_abc',
            refresh_token='refresh_token_xyz',
            token_expires_in=3600,
            profile_data={'name': 'Test User'}
        )
        
        # Verify account was created
        assert account.user_id == 'user123'
        assert account.provider == 'google'
        assert account.provider_user_id == 'google123'
        assert account.email == 'test@example.com'
        
        # Verify tokens were encrypted
        mock_encryption_instance.encrypt.assert_any_call('access_token_abc')
        mock_encryption_instance.encrypt.assert_any_call('refresh_token_xyz')
        
        # Verify Elasticsearch was called
        mock_es_instance.index.assert_called_once()
    
    @patch('app.services.oauth_account_service.ElasticsearchService')
    @patch('app.services.oauth_account_service.EncryptionService')
    def test_get_oauth_account(self, mock_encryption, mock_es, app):
        """Test retrieving OAuth account."""
        # Setup mock
        mock_es_instance = Mock()
        mock_es_instance.search.return_value = {
            'hits': {
                'total': {'value': 1},
                'hits': [{
                    '_id': 'account123',
                    '_source': {
                        'user_id': 'user123',
                        'provider': 'google',
                        'provider_user_id': 'google123',
                        'email': 'test@example.com',
                        'access_token_encrypted': 'encrypted_token',
                        'created_at': '2024-01-01T00:00:00'
                    }
                }]
            }
        }
        mock_es.return_value = mock_es_instance
        
        service = OAuthAccountService()
        
        # Get account
        account = service.get_oauth_account('google', 'google123')
        
        # Verify
        assert account is not None
        assert account.provider == 'google'
        assert account.provider_user_id == 'google123'


class TestOAuthService:
    """Test OAuth service orchestration."""
    
    @patch('app.services.oauth_service.get_provider')
    def test_initiate_login(self, mock_get_provider, app, client):
        """Test initiating OAuth login flow."""
        # Setup mock provider
        mock_provider = Mock()
        mock_provider.generate_state.return_value = 'test_state'
        mock_provider.get_authorization_url.return_value = (
            'https://accounts.google.com/auth?client_id=test',
            'code_verifier_123'
        )
        mock_get_provider.return_value = mock_provider
        
        with client.session_transaction() as session:
            # Service should store state and verifier in session
            pass
        
        service = OAuthService()
        
        with app.test_request_context():
            auth_url, error = service.initiate_login('google')
        
        # Verify
        assert error is None
        assert auth_url == 'https://accounts.google.com/auth?client_id=test'
        mock_provider.get_authorization_url.assert_called_once()
    
    @patch('app.services.oauth_service.get_provider')
    @patch('app.services.oauth_service.User')
    @patch('app.services.oauth_service.OAuthAccountService')
    def test_handle_callback_existing_user(self, mock_account_service_class, 
                                          mock_user, mock_get_provider, app):
        """Test handling OAuth callback for existing user."""
        # Setup mocks
        mock_provider = Mock()
        mock_provider.validate_state.return_value = True
        mock_provider.exchange_code_for_token.return_value = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 3600
        }
        mock_provider.get_user_info.return_value = {
            'provider_user_id': 'google123',
            'email': 'test@example.com',
            'email_verified': True,
            'name': 'Test User'
        }
        mock_get_provider.return_value = mock_provider
        
        # Mock existing OAuth account
        mock_oauth_account = Mock()
        mock_oauth_account.user_id = 'user123'
        mock_oauth_account.id = 'oauth_account_123'
        
        mock_account_service = Mock()
        mock_account_service.get_oauth_account.return_value = mock_oauth_account
        mock_account_service_class.return_value = mock_account_service
        
        # Mock existing user
        mock_existing_user = Mock()
        mock_existing_user.id = 'user123'
        mock_existing_user.username = 'testuser'
        mock_user.get_by_id.return_value = mock_existing_user
        
        service = OAuthService()
        
        with app.test_request_context():
            from flask import session
            session['oauth_google_state'] = 'test_state'
            session['oauth_google_code_verifier'] = 'code_verifier_123'
            session['oauth_google_redirect_uri'] = 'http://localhost/callback'
            
            user, error = service.handle_callback('google', 'auth_code_xyz', 'test_state')
        
        # Verify
        assert error is None
        assert user is not None
        assert user.username == 'testuser'
        
        # Verify tokens were updated
        mock_account_service.update_tokens.assert_called_once()


class TestOAuthRoutes:
    """Test OAuth routes."""
    
    def test_login_route_redirects_to_provider(self, client, app):
        """Test /oauth/login/<provider> redirects to provider."""
        app.config['OAUTH_ENABLED'] = True
        
        with patch('app.routes.oauth.OAuthService') as mock_service_class:
            mock_service = Mock()
            mock_service.initiate_login.return_value = (
                'https://accounts.google.com/auth?test',
                None
            )
            mock_service_class.return_value = mock_service
            
            response = client.get('/oauth/login/google')
            
            # Should redirect to authorization URL
            assert response.status_code == 302
            assert 'accounts.google.com' in response.location
    
    def test_login_route_disabled(self, client, app):
        """Test OAuth login when disabled."""
        app.config['OAUTH_ENABLED'] = False
        
        response = client.get('/oauth/login/google', follow_redirects=False)
        
        # Should redirect to regular login
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_callback_with_error(self, client, app):
        """Test callback when provider returns error."""
        app.config['OAUTH_ENABLED'] = True
        
        response = client.get(
            '/oauth/callback/google?error=access_denied&error_description=User%20denied',
            follow_redirects=False
        )
        
        # Should redirect to login with error
        assert response.status_code == 302


# Integration test helper
def test_end_to_end_oauth_flow_mock():
    """
    End-to-end test of OAuth flow (mocked).
    
    This demonstrates the full flow:
    1. User clicks "Sign in with Google"
    2. Redirect to Google
    3. Google redirects back with code
    4. Exchange code for token
    5. Fetch user profile
    6. Create/link user account
    7. Login user
    """
    # This would require a full integration test setup
    # For now, the individual unit tests above cover each step
    pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
