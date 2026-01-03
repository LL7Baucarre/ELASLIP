"""GitHub OAuth 2.0 provider."""

from typing import Dict
from .base import BaseOAuthProvider


class GitHubOAuthProvider(BaseOAuthProvider):
    """
    GitHub OAuth 2.0 provider implementation.
    
    Note: GitHub OAuth is OAuth 2.0 but NOT OpenID Connect.
    GitHub does not support PKCE, so we disable it.
    User information requires a separate API call to /user endpoint.
    """
    
    PROVIDER_NAME = 'github'
    
    # GitHub OAuth endpoints
    AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize'
    TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token'
    USERINFO_ENDPOINT = 'https://api.github.com/user'
    
    # GitHub doesn't support 'openid' scope or PKCE
    DEFAULT_SCOPES = ['read:user', 'user:email']
    PKCE_ENABLED = False
    
    def _normalize_user_info(self, raw_profile: Dict) -> Dict:
        email = raw_profile.get('email')
        
        if not email:
            email = f"{raw_profile.get('login')}@users.noreply.github.com"
        
        name = raw_profile.get('name', '')
        name_parts = name.split(' ', 1) if name else ['', '']
        given_name = name_parts[0] if len(name_parts) > 0 else ''
        family_name = name_parts[1] if len(name_parts) > 1 else ''
        
        return {
            'provider_user_id': str(raw_profile.get('id')),
            'email': email,
            'email_verified': True,
            'name': name,
            'given_name': given_name,
            'family_name': family_name,
            'picture': raw_profile.get('avatar_url'),
            'username': raw_profile.get('login'),
            'bio': raw_profile.get('bio'),
            'company': raw_profile.get('company'),
            'location': raw_profile.get('location'),
        }
    
    def _get_additional_auth_params(self) -> Dict:
        return {}
    
    def get_display_name(self) -> str:
        return 'GitHub'
    
    def exchange_code_for_token(self, code: str, redirect_uri: str, 
                                code_verifier: str) -> Dict:
        from authlib.integrations.requests_client import OAuth2Session
        
        session = OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=redirect_uri,
        )
        
        token = session.fetch_token(
            self.TOKEN_ENDPOINT,
            authorization_response=None,
            code=code,
            headers={'Accept': 'application/json'}
        )
        
        return token
    
    def get_display_name(self) -> str:
        return 'GitHub'
