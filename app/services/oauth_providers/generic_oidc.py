"""Generic OpenID Connect (OIDC) provider."""

from typing import Dict
import requests
from flask import current_app
from .base import BaseOAuthProvider


class GenericOIDCProvider(BaseOAuthProvider):
    PROVIDER_NAME = 'oidc'
    DEFAULT_SCOPES = ['openid', 'profile', 'email']
    
    def __init__(self):
        self.discovery_url = current_app.config.get('OAUTH_OIDC_DISCOVERY_URL', '')
        
        if not self.discovery_url:
            raise ValueError('OAUTH_OIDC_DISCOVERY_URL is required for OIDC provider')
        
        super().__init__()
        self._discover_endpoints()
    
    def _discover_endpoints(self):
        try:
            response = requests.get(self.discovery_url, timeout=10)
            response.raise_for_status()
            config = response.json()
            
            self.AUTHORIZATION_ENDPOINT = config.get('authorization_endpoint')
            self.TOKEN_ENDPOINT = config.get('token_endpoint')
            self.USERINFO_ENDPOINT = config.get('userinfo_endpoint')
            
            if not all([self.AUTHORIZATION_ENDPOINT, self.TOKEN_ENDPOINT, self.USERINFO_ENDPOINT]):
                raise ValueError('OIDC discovery response missing required endpoints')
            
            self.issuer = config.get('issuer')
            self.jwks_uri = config.get('jwks_uri')
            self.supported_scopes = config.get('scopes_supported', self.DEFAULT_SCOPES)
            
        except requests.RequestException as e:
            raise Exception(f'Failed to discover OIDC endpoints from {self.discovery_url}: {str(e)}')
    
    def _normalize_user_info(self, raw_profile: Dict) -> Dict:
        return {
            'provider_user_id': raw_profile.get('sub'),
            'email': raw_profile.get('email'),
            'email_verified': raw_profile.get('email_verified', False),
            'name': raw_profile.get('name'),
            'given_name': raw_profile.get('given_name'),
            'family_name': raw_profile.get('family_name'),
            'picture': raw_profile.get('picture'),
            'preferred_username': raw_profile.get('preferred_username'),
            'locale': raw_profile.get('locale'),
        }
    
    def _get_additional_auth_params(self) -> Dict:
        return {}
    
    def get_display_name(self) -> str:
        return current_app.config.get('OAUTH_OIDC_PROVIDER_NAME', 'OIDC')
