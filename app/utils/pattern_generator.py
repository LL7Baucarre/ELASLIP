"""Pattern Generator and Validator for STIX patterns."""

import re
from typing import Tuple, Optional


class PatternGenerator:
    """Generate and validate STIX patterns from IOC values."""
    
    # Validation regex patterns for each IOC type
    VALIDATORS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'ipv4': re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ),
        'domain': re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ),
        'email': re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ),
        'url': re.compile(
            r'^https?://[^\s/$.?#].[^\s]*$',
            re.IGNORECASE
        ),
        'asn': re.compile(r'^AS\d+$', re.IGNORECASE)
    }
    
    # STIX pattern templates
    PATTERN_TEMPLATES = {
        'md5': "[file:hashes.MD5 = '{}']",
        'sha1': "[file:hashes.SHA1 = '{}']",
        'sha256': "[file:hashes.SHA256 = '{}']",
        'ipv4': "[ipv4-addr:value = '{}']",
        'domain': "[domain-name:value = '{}']",
        'email': "[email-addr:value = '{}']",
        'url': "[url:value = '{}']",
        'asn': "[autonomous-system:number = {}]"
    }
    
    # Supported IOC types
    SUPPORTED_TYPES = list(PATTERN_TEMPLATES.keys())
    
    @classmethod
    def validate_value(cls, ioc_type: str, value: str) -> bool:
        """
        Validate an IOC value against its type.
        
        Args:
            ioc_type: Type of IOC (md5, sha1, sha256, ipv4, domain, email, url)
            value: The value to validate
        
        Returns:
            True if valid, False otherwise
        """
        ioc_type = ioc_type.lower()
        
        if ioc_type not in cls.VALIDATORS:
            return False
        
        validator = cls.VALIDATORS[ioc_type]
        return bool(validator.match(value))
    
    @classmethod
    def detect_type(cls, value: str) -> Optional[str]:
        """
        Auto-detect the IOC type from a value.
        
        Args:
            value: The IOC value to analyze
        
        Returns:
            Detected IOC type or None if not recognized
        """
        value = value.strip()
        
        # Check hashes by length first (most specific)
        if cls.VALIDATORS['md5'].match(value):
            return 'md5'
        if cls.VALIDATORS['sha1'].match(value):
            return 'sha1'
        if cls.VALIDATORS['sha256'].match(value):
            return 'sha256'
        
        # Check URL before domain (URL contains domain)
        if cls.VALIDATORS['url'].match(value):
            return 'url'
        
        # Check email before domain
        if cls.VALIDATORS['email'].match(value):
            return 'email'
        
        # Check IP
        if cls.VALIDATORS['ipv4'].match(value):
            return 'ipv4'
        
        # Check ASN
        if cls.VALIDATORS['asn'].match(value):
            return 'asn'
        
        # Check domain last
        if cls.VALIDATORS['domain'].match(value):
            return 'domain'
        
        return None
    
    @classmethod
    def generate_pattern(cls, ioc_type: str, value: str) -> str:
        """
        Generate a STIX pattern from IOC type and value.
        
        Args:
            ioc_type: Type of IOC
            value: The IOC value
        
        Returns:
            STIX pattern string
        
        Raises:
            ValueError: If type not supported or value invalid
        """
        ioc_type = ioc_type.lower()
        
        if ioc_type not in cls.PATTERN_TEMPLATES:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        
        if not cls.validate_value(ioc_type, value):
            raise ValueError(f"Invalid {ioc_type} value: {value}")
        
        # Normalize hash values to lowercase
        if ioc_type in ['md5', 'sha1', 'sha256']:
            value = value.lower()
        
        # For ASN, extract just the number
        if ioc_type == 'asn':
            asn_number = value.upper().replace('AS', '')
            return cls.PATTERN_TEMPLATES[ioc_type].format(asn_number)
        
        return cls.PATTERN_TEMPLATES[ioc_type].format(value)
    
    @classmethod
    def extract_value_from_pattern(cls, pattern: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract IOC type and value from a STIX pattern.
        
        Args:
            pattern: STIX pattern string
        
        Returns:
            Tuple of (ioc_type, value) or (None, None) if not extractable
        """
        # Pattern matchers for each type
        extractors = {
            'md5': re.compile(r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]"),
            'sha1': re.compile(r"\[file:hashes\.SHA1\s*=\s*'([^']+)'\]"),
            'sha256': re.compile(r"\[file:hashes\.SHA256\s*=\s*'([^']+)'\]"),
            'ipv4': re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
            'domain': re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
            'email': re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]"),
            'url': re.compile(r"\[url:value\s*=\s*'([^']+)'\]"),
            'asn': re.compile(r"\[autonomous-system:number\s*=\s*(\d+)\]")
        }
        
        for ioc_type, extractor in extractors.items():
            match = extractor.search(pattern)
            if match:
                value = match.group(1)
                # For ASN, prepend AS prefix
                if ioc_type == 'asn':
                    value = f'AS{value}'
                return ioc_type, value
        
        return None, None
    
    @classmethod
    def get_pattern_hash(cls, pattern: str) -> str:
        """
        Generate a unique hash for a pattern (used for deduplication).
        
        Args:
            pattern: STIX pattern string
        
        Returns:
            Hash string for the pattern
        """
        import hashlib
        
        # Normalize the pattern (lowercase, remove extra spaces)
        normalized = pattern.lower().strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        
        return hashlib.sha256(normalized.encode()).hexdigest()
