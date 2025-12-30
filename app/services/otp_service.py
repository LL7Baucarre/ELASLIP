"""OTP (One-Time Password) Service for MFA authentication."""

import io
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

import pyotp
import qrcode
from flask import current_app
from redis import Redis


class OTPService:
    """Service for managing OTP (TOTP) authentication."""
    
    # Time-based OTP configuration
    TOTP_ISSUER = "ELASLIP"
    TOTP_PERIOD = 30  # 30 seconds per code
    TOTP_DIGITS = 6   # 6-digit codes
    
    # Backup codes configuration
    BACKUP_CODE_LENGTH = 12
    BACKUP_CODE_COUNT = 10
    
    # Temp session configuration
    TEMP_SESSION_PREFIX = "otp:temp_session:"
    TEMP_SESSION_EXPIRY = 300  # 5 minutes in seconds
    MAX_OTP_ATTEMPTS = 5
    
    def __init__(self):
        """Initialize OTP service."""
        # Get Redis configuration from Flask config or environment
        redis_host = current_app.config.get('REDIS_HOST', 'redis')
        redis_port = current_app.config.get('REDIS_PORT', 6379)
        redis_db = current_app.config.get('REDIS_DB', 0)
        
        self.redis = Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True
        )
    
    def generate_secret(self, length: int = 32) -> str:
        """
        Generate a random base32-encoded secret for OTP.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            Base32-encoded secret string
        """
        random_bytes = secrets.token_bytes(length)
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str) -> bytes:
        """
        Generate a QR code for OTP setup.
        
        Args:
            username: User's username/email
            secret: OTP secret (base32)
            
        Returns:
            PNG image bytes of the QR code
        """
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.TOTP_ISSUER
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        return img_bytes.getvalue()
    
    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify a TOTP token against a secret.
        
        Args:
            secret: Base32-encoded OTP secret
            token: 6-digit code to verify
            window: Number of time windows to check (for clock skew)
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            # Check current and adjacent time windows (for clock skew tolerance)
            return totp.verify(token, valid_window=window)
        except Exception:
            return False
    
    def generate_backup_codes(self, count: int = BACKUP_CODE_COUNT) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate codes in format: ABC123-DEF456
            code = secrets.token_hex(self.BACKUP_CODE_LENGTH // 2).upper()
            # Format as XXX-XXX for readability
            formatted = f"{code[:3]}-{code[3:6]}-{code[6:]}"
            codes.append(formatted)
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """
        Hash a backup code for storage.
        
        Args:
            code: Backup code to hash
            
        Returns:
            Hashed code
        """
        # Import here to avoid circular imports
        import hashlib
        return hashlib.sha256(code.replace('-', '').encode()).hexdigest()
    
    def verify_backup_code(self, user, code: str) -> bool:
        """
        Verify a backup code against user's stored codes.
        
        Args:
            user: User object with otp_backup_codes
            code: Backup code to verify
            
        Returns:
            True if code matches (but not yet consumed)
        """
        if not hasattr(user, 'otp_backup_codes') or not user.otp_backup_codes:
            return False
        
        code_hash = self.hash_backup_code(code)
        return code_hash in user.otp_backup_codes
    
    def consume_backup_code(self, user, code: str) -> bool:
        """
        Consume a backup code (remove it after use).
        
        Args:
            user: User object
            code: Backup code to consume
            
        Returns:
            True if code was successfully consumed
        """
        from app.services.elasticsearch_service import ElasticsearchService
        
        if not self.verify_backup_code(user, code):
            return False
        
        code_hash = self.hash_backup_code(code)
        backup_codes = user.otp_backup_codes or []
        
        # Remove the used code
        backup_codes = [c for c in backup_codes if c != code_hash]
        
        # Update user
        es = ElasticsearchService()
        es.update('users', user.id, {
            'doc': {
                'otp': {
                    'enabled': user.otp_enabled,
                    'secret': user.otp_secret,
                    'backup_codes': backup_codes,
                    'verified_at': user.otp_verified_at,
                    'created_at': user.otp_created_at
                }
            }
        })
        
        return True
    
    def enable_otp(self, user, secret: str, backup_codes: List[str]) -> bool:
        """
        Enable OTP for a user.
        
        Args:
            user: User object
            secret: OTP secret (base32)
            backup_codes: List of backup codes
            
        Returns:
            True if OTP was enabled successfully
        """
        from app.services.elasticsearch_service import ElasticsearchService
        
        # Hash backup codes for storage
        hashed_codes = [self.hash_backup_code(code) for code in backup_codes]
        
        # Update user
        es = ElasticsearchService()
        now = datetime.utcnow().isoformat()
        
        es.update('users', user.id, {
            'doc': {
                'otp': {
                    'enabled': True,
                    'secret': secret,
                    'backup_codes': hashed_codes,
                    'verified_at': now,
                    'created_at': now
                }
            }
        })
        
        return True
    
    def disable_otp(self, user) -> bool:
        """
        Disable OTP for a user.
        
        Args:
            user: User object
            
        Returns:
            True if OTP was disabled successfully
        """
        from app.services.elasticsearch_service import ElasticsearchService
        
        es = ElasticsearchService()
        es.update('users', user.id, {
            'doc': {
                'otp': {
                    'enabled': False,
                    'secret': None,
                    'backup_codes': [],
                    'verified_at': None,
                    'created_at': None
                }
            }
        })
        
        return True
    
    def get_otp_status(self, user) -> dict:
        """
        Get OTP status for a user.
        
        Args:
            user: User object
            
        Returns:
            Dictionary with OTP status
        """
        return {
            'enabled': getattr(user, 'otp_enabled', False),
            'verified_at': getattr(user, 'otp_verified_at', None),
            'created_at': getattr(user, 'otp_created_at', None),
            'backup_codes_count': len(getattr(user, 'otp_backup_codes', []))
        }
    
    def create_temp_session(self, user_id: str) -> str:
        """
        Create a temporary session for OTP verification.
        
        Args:
            user_id: User ID
            
        Returns:
            Temporary session token
        """
        token = secrets.token_hex(16)
        key = f"{self.TEMP_SESSION_PREFIX}{token}"
        
        session_data = {
            'user_id': user_id,
            'attempts': 0,
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Store in Redis with expiration
        self.redis.setex(
            key,
            self.TEMP_SESSION_EXPIRY,
            self._serialize_session(session_data)
        )
        
        return token
    
    def get_temp_session(self, token: str) -> Optional[dict]:
        """
        Get a temporary session.
        
        Args:
            token: Temporary session token
            
        Returns:
            Session data or None if expired/invalid
        """
        key = f"{self.TEMP_SESSION_PREFIX}{token}"
        data = self.redis.get(key)
        
        if data:
            return self._deserialize_session(data)
        return None
    
    def update_temp_session_attempts(self, token: str) -> int:
        """
        Increment attempt counter for a temporary session.
        
        Args:
            token: Temporary session token
            
        Returns:
            New attempt count
        """
        key = f"{self.TEMP_SESSION_PREFIX}{token}"
        session = self.get_temp_session(token)
        
        if not session:
            return -1
        
        session['attempts'] += 1
        
        # Check if exceeded max attempts
        if session['attempts'] >= self.MAX_OTP_ATTEMPTS:
            self.delete_temp_session(token)
            return -1
        
        # Update in Redis
        self.redis.setex(
            key,
            self.TEMP_SESSION_EXPIRY,
            self._serialize_session(session)
        )
        
        return session['attempts']
    
    def delete_temp_session(self, token: str) -> bool:
        """
        Delete a temporary session.
        
        Args:
            token: Temporary session token
            
        Returns:
            True if deleted
        """
        key = f"{self.TEMP_SESSION_PREFIX}{token}"
        return bool(self.redis.delete(key))
    
    def get_remaining_attempts(self, token: str) -> int:
        """
        Get remaining OTP attempts for a session.
        
        Args:
            token: Temporary session token
            
        Returns:
            Number of remaining attempts (0 if session invalid)
        """
        session = self.get_temp_session(token)
        if not session:
            return 0
        return self.MAX_OTP_ATTEMPTS - session['attempts']
    
    @staticmethod
    def _serialize_session(session_data: dict) -> str:
        """Serialize session data for Redis storage."""
        import json
        return json.dumps(session_data)
    
    @staticmethod
    def _deserialize_session(data: str) -> dict:
        """Deserialize session data from Redis."""
        import json
        return json.loads(data)
