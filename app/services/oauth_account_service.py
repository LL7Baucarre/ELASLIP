"""OAuth account service for managing OAuth account linkage."""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict
from flask import current_app

from app.services.elasticsearch_service import ElasticsearchService
from app.services.encryption_service import EncryptionService


class OAuthAccount:
    """Model for OAuth account linking."""
    
    def __init__(self, account_data: Dict):
        """Initialize OAuth account from data dict."""
        self.id = account_data.get('id')
        self.user_id = account_data.get('user_id')
        self.provider = account_data.get('provider')
        self.provider_user_id = account_data.get('provider_user_id')
        self.email = account_data.get('email')
        self.access_token_encrypted = account_data.get('access_token_encrypted')
        self.refresh_token_encrypted = account_data.get('refresh_token_encrypted')
        self.token_expires_at = account_data.get('token_expires_at')
        self.profile_data = account_data.get('profile_data', {})
        self.created_at = account_data.get('created_at')
        self.updated_at = account_data.get('updated_at')
    
    def to_dict(self) -> Dict:
        """Convert to dictionary (without sensitive tokens)."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'provider': self.provider,
            'provider_user_id': self.provider_user_id,
            'email': self.email,
            'token_expires_at': self.token_expires_at,
            'profile_data': self.profile_data,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }


class OAuthAccountService:
    """Service for managing OAuth account linkage and tokens."""
    
    def __init__(self):
        """Initialize service."""
        self.es = ElasticsearchService()
        self.encryption = EncryptionService()
    
    def create_oauth_account(self, user_id: str, provider: str, 
                            provider_user_id: str, email: str,
                            access_token: str, refresh_token: Optional[str],
                            token_expires_in: Optional[int],
                            profile_data: Dict) -> OAuthAccount:
        """
        Create a new OAuth account linkage.
        
        Args:
            user_id: Internal user ID
            provider: OAuth provider name ('google', 'github', etc.)
            provider_user_id: User ID from OAuth provider
            email: User email from OAuth provider
            access_token: OAuth access token
            refresh_token: OAuth refresh token (may be None)
            token_expires_in: Token expiration time in seconds (may be None)
            profile_data: Additional profile information from provider
        
        Returns:
            OAuthAccount instance
        """
        account_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        
        # Calculate token expiration
        token_expires_at = None
        if token_expires_in:
            expires_at = datetime.utcnow() + timedelta(seconds=token_expires_in)
            token_expires_at = expires_at.isoformat()
        
        # Encrypt tokens before storage
        access_token_encrypted = self.encryption.encrypt(access_token) if access_token else None
        refresh_token_encrypted = self.encryption.encrypt(refresh_token) if refresh_token else None
        
        account_data = {
            'id': account_id,
            'user_id': user_id,
            'provider': provider,
            'provider_user_id': provider_user_id,
            'email': email,
            'access_token_encrypted': access_token_encrypted,
            'refresh_token_encrypted': refresh_token_encrypted,
            'token_expires_at': token_expires_at,
            'profile_data': profile_data,
            'created_at': now,
            'updated_at': now,
        }
        
        self.es.index('oauth_accounts', account_id, account_data)
        
        return OAuthAccount(account_data)
    
    def get_oauth_account(self, provider: str, provider_user_id: str) -> Optional[OAuthAccount]:
        """
        Get OAuth account by provider and provider user ID.
        
        Args:
            provider: OAuth provider name
            provider_user_id: User ID from OAuth provider
        
        Returns:
            OAuthAccount instance or None
        """
        result = self.es.search('oauth_accounts', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'provider': provider}},
                        {'term': {'provider_user_id': provider_user_id}}
                    ]
                }
            },
            'size': 1
        })
        
        if result['hits']['total']['value'] > 0:
            hit = result['hits']['hits'][0]
            account_data = hit['_source']
            account_data['id'] = hit['_id']
            return OAuthAccount(account_data)
        
        return None
    
    def get_oauth_accounts_by_user(self, user_id: str) -> list[OAuthAccount]:
        """
        Get all OAuth accounts for a user.
        
        Args:
            user_id: Internal user ID
        
        Returns:
            List of OAuthAccount instances
        """
        result = self.es.search('oauth_accounts', {
            'query': {'term': {'user_id.keyword': user_id}},
            'size': 100
        })
        
        accounts = []
        for hit in result['hits']['hits']:
            account_data = hit['_source']
            account_data['id'] = hit['_id']
            accounts.append(OAuthAccount(account_data))
        
        return accounts
    
    def update_tokens(self, account_id: str, access_token: str, 
                     refresh_token: Optional[str], 
                     token_expires_in: Optional[int]) -> None:
        """
        Update OAuth account tokens.
        
        Args:
            account_id: OAuth account ID
            access_token: New access token
            refresh_token: New refresh token (may be None)
            token_expires_in: Token expiration time in seconds (may be None)
        """
        now = datetime.utcnow().isoformat()
        
        # Calculate token expiration
        token_expires_at = None
        if token_expires_in:
            expires_at = datetime.utcnow() + timedelta(seconds=token_expires_in)
            token_expires_at = expires_at.isoformat()
        
        # Encrypt tokens
        access_token_encrypted = self.encryption.encrypt(access_token) if access_token else None
        refresh_token_encrypted = self.encryption.encrypt(refresh_token) if refresh_token else None
        
        update_data = {
            'access_token_encrypted': access_token_encrypted,
            'token_expires_at': token_expires_at,
            'updated_at': now,
        }
        
        if refresh_token_encrypted:
            update_data['refresh_token_encrypted'] = refresh_token_encrypted
        
        self.es.update('oauth_accounts', account_id, {'doc': update_data})
    
    def get_decrypted_access_token(self, account: OAuthAccount) -> Optional[str]:
        """
        Get decrypted access token from OAuth account.
        
        Args:
            account: OAuthAccount instance
        
        Returns:
            Decrypted access token or None
        """
        if not account.access_token_encrypted:
            return None
        
        return self.encryption.decrypt(account.access_token_encrypted)
    
    def get_decrypted_refresh_token(self, account: OAuthAccount) -> Optional[str]:
        """
        Get decrypted refresh token from OAuth account.
        
        Args:
            account: OAuthAccount instance
        
        Returns:
            Decrypted refresh token or None
        """
        if not account.refresh_token_encrypted:
            return None
        
        return self.encryption.decrypt(account.refresh_token_encrypted)
    
    def delete_oauth_account(self, account_id: str) -> None:
        """
        Delete an OAuth account linkage.
        
        Args:
            account_id: OAuth account ID
        """
        self.es.delete('oauth_accounts', account_id)
    
    def is_token_expired(self, account: OAuthAccount) -> bool:
        """
        Check if OAuth account's access token is expired.
        
        Args:
            account: OAuthAccount instance
        
        Returns:
            True if expired, False otherwise
        """
        if not account.token_expires_at:
            return False  # No expiration set
        
        from datetime import datetime
        expires_at = datetime.fromisoformat(account.token_expires_at)
        return datetime.utcnow() >= expires_at
