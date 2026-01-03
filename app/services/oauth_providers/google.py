"""Google OAuth 2.0 / OpenID Connect provider."""

from typing import Dict
from .base import BaseOAuthProvider


class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Google OAuth 2.0 / OpenID Connect provider implementation.
    
    Uses Google's OpenID Connect discovery for endpoint configuration.
    Supports automatic profile fetching and email verification.
    """
    
    PROVIDER_NAME = 'google'
    
    # Google OAuth endpoints
    AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
    TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
    USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo'
    
    # Request access to user's profile and email
    DEFAULT_SCOPES = ['openid', 'profile', 'email']
    
    def _normalize_user_info(self, raw_profile: Dict) -> Dict:
        return {
            'provider_user_id': raw_profile.get('sub'),
            'email': raw_profile.get('email'),
            'email_verified': raw_profile.get('email_verified', False),
            'name': raw_profile.get('name'),
            'given_name': raw_profile.get('given_name'),
            'family_name': raw_profile.get('family_name'),
            'picture': raw_profile.get('picture'),
            'locale': raw_profile.get('locale'),
        }
    
    def _get_additional_auth_params(self) -> Dict:
        return {
            'access_type': 'offline',
            'prompt': 'select_account',
        }
    
    def get_display_name(self) -> str:
        return 'Google'
