"""OAuth service for orchestrating OAuth authentication flows."""

import logging
import secrets
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
from flask import session, url_for, current_app

from app.auth import User
from app.services.oauth_providers import get_provider, get_enabled_providers
from app.services.oauth_account_service import OAuthAccountService
from app.services.audit_service import AuditService


logger = logging.getLogger(__name__)


class OAuthService:
    """
    Service for orchestrating OAuth 2.0 authentication flows.
    
    Handles:
    - Authorization URL generation
    - Callback processing
    - User account creation/linking
    - Token management
    """
    
    def __init__(self):
        """Initialize OAuth service."""
        self.account_service = OAuthAccountService()
        self.audit_service = AuditService()
    
    def initiate_login(self, provider_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Initiate OAuth login flow.
        
        Args:
            provider_name: OAuth provider name ('google', 'github', etc.)
        
        Returns:
            Tuple of (authorization_url, error_message)
            If successful, authorization_url is set and error_message is None
            If failed, authorization_url is None and error_message is set
        """
        # Get provider
        provider = get_provider(provider_name)
        if not provider:
            return None, f'OAuth provider "{provider_name}" is not enabled or configured'
        
        state = provider.generate_state()
        redirect_uri = url_for('oauth.callback', provider=provider_name, _external=True)
        
        try:
            auth_url, code_verifier = provider.get_authorization_url(
                state=state,
                redirect_uri=redirect_uri
            )
        except Exception as e:
            logger.error(f'Error generating OAuth authorization URL for {provider_name}: {str(e)}')
            return None, 'Failed to generate authorization URL'
        
        session[f'oauth_{provider_name}_state'] = state
        session[f'oauth_{provider_name}_code_verifier'] = code_verifier
        session[f'oauth_{provider_name}_redirect_uri'] = redirect_uri
        session.modified = True
        
        logger.info(f'OAuth login initiated for provider: {provider_name}')
        
        return auth_url, None
    
    def handle_callback(self, provider_name: str, code: str, 
                       state: str) -> Tuple[Optional[User], Optional[str]]:
        """
        Handle OAuth callback after user authorizes.
        
        Args:
            provider_name: OAuth provider name
            code: Authorization code from provider
            state: State parameter from provider (for CSRF protection)
        
        Returns:
            Tuple of (user, error_message)
            If successful, user is set and error_message is None
            If failed, user is None and error_message is set
        """
        # Get provider
        provider = get_provider(provider_name)
        if not provider:
            return None, f'OAuth provider "{provider_name}" is not enabled'
        
        session_state = session.get(f'oauth_{provider_name}_state')
        
        if not provider.validate_state(state, session_state):
            logger.warning(f'OAuth state validation failed for {provider_name}')
            return None, 'Invalid OAuth state. Possible CSRF attack detected.'
        
        code_verifier = session.get(f'oauth_{provider_name}_code_verifier')
        redirect_uri = session.get(f'oauth_{provider_name}_redirect_uri')
        
        if not code_verifier or not redirect_uri:
            return None, 'OAuth session expired. Please try again.'
        
        # Exchange code for token
        try:
            token_response = provider.exchange_code_for_token(
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier
            )
        except Exception as e:
            logger.error(f'OAuth token exchange failed for {provider_name}: {str(e)}')
            return None, 'Failed to exchange authorization code for token'
        
        access_token = token_response.get('access_token')
        refresh_token = token_response.get('refresh_token')
        expires_in = token_response.get('expires_in')
        
        if not access_token:
            return None, 'No access token received from provider'
        
        try:
            user_profile = provider.get_user_info(access_token)
        except Exception as e:
            logger.error(f'Failed to fetch user profile from {provider_name}: {str(e)}')
            return None, 'Failed to fetch user profile from provider'
        
        provider_user_id = user_profile.get('provider_user_id')
        email = user_profile.get('email')
        email_verified = user_profile.get('email_verified', False)
        
        if not provider_user_id or not email:
            return None, 'Provider did not return required user information'
        
        oauth_account = self.account_service.get_oauth_account(provider_name, provider_user_id)
        
        if oauth_account:
            user = User.get_by_id(oauth_account.user_id)
            
            if not user:
                logger.info(f'Creating new user for orphaned OAuth account: {oauth_account.id}')
                default_role = current_app.config.get('OAUTH_DEFAULT_ROLE', 'viewer')
                
                username = email.split('@')[0]
                counter = 1
                original_username = username
                while User.get_by_username(username):
                    username = f'{original_username}{counter}'
                    counter += 1
                
                user, error = User.create(
                    username=username,
                    email=email,
                    password=User.hash_password(User.generate_random_password()),
                    is_admin=False,
                    role=default_role
                )
                
                if not user:
                    logger.error(f'Failed to create user for OAuth: {error}')
                    return None, f'Failed to create user account: {error}'
            
            self.account_service.update_tokens(
                account_id=oauth_account.id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_expires_in=expires_in
            )
            
            user.update_last_login()
            
            self.audit_service.log(
                action='oauth_login',
                entity_type='user',
                entity_id=user.id,
                user_id=user.id,
                username=user.username,
                changes={'provider': provider_name, 'email': email}
            )
            
            logger.info(f'Existing OAuth account logged in via: {user.username}')
            
            return user, None
        
        existing_user = None
        if email:
            from app.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            result = es.search('users', {
                'query': {
                    'term': {'email.keyword': email.lower()}
                },
                'size': 1
            })
            
            if result['hits']['total']['value'] > 0:
                hit = result['hits']['hits'][0]
                user_data = hit['_source']
                user_data['id'] = hit['_id']
                existing_user = User(user_data)
        
        auto_link = current_app.config.get('OAUTH_AUTO_LINK_BY_EMAIL', False)
        
        if existing_user:
            if auto_link:
                user = existing_user
                logger.info(f'Linking OAuth account to existing user: {user.username}')
            else:
                return None, f'An account with email {email} already exists. Please log in with your password and link OAuth from your profile.'
        elif current_app.config.get('OAUTH_AUTO_CREATE_USER', True):
            default_role = current_app.config.get('OAUTH_DEFAULT_ROLE', 'viewer')
            
            username = email.split('@')[0]
            
            counter = 1
            original_username = username
            while User.get_by_username(username):
                username = f'{original_username}{counter}'
                counter += 1
            
            user, error = User.create(
                username=username,
                email=email,
                password=User.hash_password(User.generate_random_password()),
                is_admin=False,
                role=default_role
            )
            
            if not user:
                logger.error(f'Failed to create user for OAuth: {error}')
                return None, f'Failed to create user account: {error}'
        else:
            return None, 'Account does not exist. Auto-registration is disabled.'
        
        oauth_account = self.account_service.create_oauth_account(
            user_id=user.id,
            provider=provider_name,
            provider_user_id=provider_user_id,
            email=email,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_in=expires_in,
            profile_data=user_profile
        )
        
        user.update_last_login()
        
        self.audit_service.log(
            action='oauth_account_created',
            entity_type='oauth_account',
            entity_id=oauth_account.id if oauth_account else user.id,
            user_id=user.id,
            username=user.username,
            changes={
                'provider': provider_name,
                'email': email,
                'auto_created': not existing_user
            }
        )
        
        session.pop(f'oauth_{provider_name}_state', None)
        session.pop(f'oauth_{provider_name}_code_verifier', None)
        session.pop(f'oauth_{provider_name}_redirect_uri', None)
        
        return user, None
    
    def get_enabled_providers_info(self) -> Dict[str, Dict]:
        """
        Get information about enabled OAuth providers for UI display.
        
        Returns:
            Dict mapping provider name to provider info:
            {
                'google': {
                    'name': 'Google',
                    'display_name': 'Google',
                    'button_style': 'oauth-btn-google'
                },
                ...
            }
        """
        providers = get_enabled_providers()
        
        info = {}
        for name, provider in providers.items():
            info[name] = {
                'name': name,
                'display_name': provider.get_display_name(),
                'button_style': provider.get_button_style()
            }
        
        return info
    
    @staticmethod
    def generate_random_password(length: int = 32) -> str:
        """Generate a random password for OAuth-only users."""
        import string
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))


# Add method to User class for random password generation
User.generate_random_password = lambda length=32: OAuthService.generate_random_password(length)
