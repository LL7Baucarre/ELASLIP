"""OAuth provider registry and factory."""

from typing import Dict, Type, Optional
from flask import current_app

from .base import BaseOAuthProvider
from .google import GoogleOAuthProvider
from .github import GitHubOAuthProvider
from .generic_oidc import GenericOIDCProvider


# Provider registry
PROVIDERS: Dict[str, Type[BaseOAuthProvider]] = {
    'google': GoogleOAuthProvider,
    'github': GitHubOAuthProvider,
    'oidc': GenericOIDCProvider,
}


def get_provider(provider_name: str) -> Optional[BaseOAuthProvider]:
    """
    Get an initialized OAuth provider by name.
    
    Args:
        provider_name: Name of the provider ('google', 'github', 'oidc')
    
    Returns:
        Initialized provider instance or None if not enabled/configured
    """
    provider_class = PROVIDERS.get(provider_name.lower())
    
    if not provider_class:
        return None
    
    # Check if provider is enabled in config
    enabled_key = f'OAUTH_{provider_name.upper()}_ENABLED'
    if not current_app.config.get(enabled_key, False):
        return None
    
    return provider_class()


def get_enabled_providers() -> Dict[str, BaseOAuthProvider]:
    """
    Get all enabled OAuth providers.
    
    Returns:
        Dictionary mapping provider name to initialized provider instance
    """
    enabled = {}
    
    for name in PROVIDERS.keys():
        provider = get_provider(name)
        if provider:
            enabled[name] = provider
    
    return enabled


__all__ = [
    'BaseOAuthProvider',
    'GoogleOAuthProvider',
    'GitHubOAuthProvider',
    'GenericOIDCProvider',
    'get_provider',
    'get_enabled_providers',
    'PROVIDERS',
]
