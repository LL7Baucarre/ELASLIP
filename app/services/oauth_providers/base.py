"""Base OAuth provider abstract class."""

import secrets
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode
from flask import current_app, url_for

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7636 import create_s256_code_challenge


class BaseOAuthProvider(ABC):
    """
    Abstract base class for OAuth 2.0 / OpenID Connect providers.
    
    Implements common OAuth flow logic with provider-specific customization points.
    Uses PKCE (Proof Key for Code Exchange) for enhanced security when supported.
    """
    
    # Provider-specific constants (override in subclasses)
    PROVIDER_NAME = 'base'
    AUTHORIZATION_ENDPOINT = ''
    TOKEN_ENDPOINT = ''
    USERINFO_ENDPOINT = ''
    DEFAULT_SCOPES = ['openid', 'profile', 'email']
    PKCE_ENABLED = True  # Override to False for providers that don't support PKCE
    
    def __init__(self):
        """Initialize provider with configuration from Flask app config."""
        self.client_id = self._get_config('CLIENT_ID')
        self.client_secret = self._get_config('CLIENT_SECRET')
        
        if not self.client_id or not self.client_secret:
            raise ValueError(
                f'OAuth provider {self.PROVIDER_NAME} is enabled but CLIENT_ID or CLIENT_SECRET is missing'
            )
    
    def _get_config(self, key: str) -> str:
        """Get provider-specific configuration value."""
        config_key = f'OAUTH_{self.PROVIDER_NAME.upper()}_{key}'
        return current_app.config.get(config_key, '')
    
    def get_authorization_url(self, state: str, redirect_uri: str, 
                             scopes: Optional[list] = None) -> Tuple[str, str]:
        if scopes is None:
            scopes = self.DEFAULT_SCOPES
        
        code_verifier = None
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state,
        }
        
        # Only use PKCE if provider supports it
        if self.PKCE_ENABLED:
            code_verifier = secrets.token_urlsafe(64)
            code_challenge = create_s256_code_challenge(code_verifier)
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'
        
        params.update(self._get_additional_auth_params())
        
        auth_url = f'{self.AUTHORIZATION_ENDPOINT}?{urlencode(params)}'
        
        return auth_url, code_verifier
    
    def exchange_code_for_token(self, code: str, redirect_uri: str, 
                                code_verifier: str) -> Dict:
        session = OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=redirect_uri,
        )
        
        token_params = {
            'authorization_response': None,
            'code': code,
        }
        
        # Only include code_verifier if PKCE is enabled
        if self.PKCE_ENABLED and code_verifier:
            token_params['code_verifier'] = code_verifier
        
        token = session.fetch_token(self.TOKEN_ENDPOINT, **token_params)
        
        return token
    
    def get_user_info(self, access_token: str) -> Dict:
        session = OAuth2Session(token={'access_token': access_token})
        response = session.get(self.USERINFO_ENDPOINT)
        response.raise_for_status()
        
        raw_profile = response.json()
        return self._normalize_user_info(raw_profile)
    
    @abstractmethod
    def _normalize_user_info(self, raw_profile: Dict) -> Dict:
        """Normalize provider-specific user info to standard format."""
        pass
    
    def _get_additional_auth_params(self) -> Dict:
        return {}
    
    def get_display_name(self) -> str:
        return self.PROVIDER_NAME.capitalize()
    
    def get_button_style(self) -> str:
        return f'oauth-btn oauth-btn-{self.PROVIDER_NAME}'
    
    def validate_state(self, provided_state: str, session_state: str) -> bool:
        if not provided_state or not session_state:
            return False
        return secrets.compare_digest(provided_state, session_state)
    
    def generate_state(self) -> str:
        return secrets.token_urlsafe(32)
