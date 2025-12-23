"""Encryption Service for securing sensitive data at rest."""

import os
import base64
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionService:
    """Service for encrypting and decrypting sensitive data."""
    
    _instance = None
    _fernet = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize the Fernet cipher with the encryption key."""
        encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if encryption_key:
            # If a full Fernet key is provided, use it directly
            try:
                self._fernet = Fernet(encryption_key.encode())
            except Exception:
                # If the key is not a valid Fernet key, derive one
                self._fernet = self._derive_key(encryption_key)
        else:
            # Generate a key from SECRET_KEY as fallback
            secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
            self._fernet = self._derive_key(secret_key)
    
    def _derive_key(self, password: str) -> Fernet:
        """Derive a Fernet key from a password."""
        salt = b'elasmisp_salt_v1'  # Static salt for consistent key derivation
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return plaintext
        
        encrypted = self._fernet.encrypt(plaintext.encode())
        return encrypted.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            ciphertext: The encrypted string to decrypt
            
        Returns:
            The decrypted plaintext string
        """
        if not ciphertext:
            return ciphertext
        
        try:
            decrypted = self._fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception:
            # If decryption fails, return the original (might be unencrypted legacy data)
            return ciphertext
    
    def is_encrypted(self, value: str) -> bool:
        """
        Check if a value appears to be encrypted.
        
        Args:
            value: The value to check
            
        Returns:
            True if the value appears to be Fernet-encrypted
        """
        if not value:
            return False
        
        # Fernet tokens start with 'gAAAA'
        return value.startswith('gAAAA')
    
    def encrypt_if_needed(self, value: str) -> str:
        """
        Encrypt a value only if it's not already encrypted.
        
        Args:
            value: The value to encrypt
            
        Returns:
            The encrypted value
        """
        if not value or self.is_encrypted(value):
            return value
        
        return self.encrypt(value)
    
    def decrypt_if_needed(self, value: str) -> str:
        """
        Decrypt a value only if it appears to be encrypted.
        
        Args:
            value: The value to decrypt
            
        Returns:
            The decrypted value
        """
        if not value or not self.is_encrypted(value):
            return value
        
        return self.decrypt(value)
    
    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key.
        
        Returns:
            A new Fernet key as a string
        """
        return Fernet.generate_key().decode()


# Singleton instance
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get the singleton encryption service instance."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service
