"""STIX 2.1 Schema and Models for IOC Manager."""

from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid

from stix2 import Indicator, Bundle, parse
from stix2.exceptions import InvalidValueError, MissingPropertiesError


class STIXIndicator:
    """Wrapper for STIX 2.1 Indicator objects."""
    
    # Supported IOC types mapping to STIX pattern format
    IOC_TYPE_PATTERNS = {
        'md5': "[file:hashes.MD5 = '{}']",
        'sha1': "[file:hashes.SHA1 = '{}']",
        'sha256': "[file:hashes.SHA256 = '{}']",
        'ipv4': "[ipv4-addr:value = '{}']",
        'domain': "[domain-name:value = '{}']",
        'email': "[email-addr:value = '{}']",
        'url': "[url:value = '{}']",
        'asn': "[autonomous-system:number = {}]"
    }
    
    def __init__(self, indicator: Indicator, sources: List[Dict] = None):
        self.indicator = indicator
        self.sources = sources or []
    
    @classmethod
    def create(cls, 
               ioc_type: str, 
               value: str, 
               labels: List[str] = None,
               source: Dict = None,
               name: str = None,
               description: str = None) -> 'STIXIndicator':
        """
        Create a new STIX Indicator from IOC type and value.
        
        Args:
            ioc_type: Type of IOC (md5, sha1, sha256, ipv4, domain, email, url)
            value: The IOC value
            labels: List of labels/tags
            source: Source information dict (name, timestamp, metadata)
            name: Optional indicator name
            description: Optional description
        
        Returns:
            STIXIndicator instance
        
        Raises:
            ValueError: If IOC type is not supported or value is invalid
        """
        from app.utils.pattern_generator import PatternGenerator
        
        # Validate the value format
        if not PatternGenerator.validate_value(ioc_type, value):
            raise ValueError(f"Invalid {ioc_type} value: {value}")
        
        # Generate STIX pattern
        pattern = PatternGenerator.generate_pattern(ioc_type, value)
        
        # Create indicator
        indicator_id = f"indicator--{uuid.uuid4()}"
        
        indicator_kwargs = {
            'id': indicator_id,
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': datetime.utcnow(),
        }
        
        if labels:
            indicator_kwargs['labels'] = labels
        
        if name:
            indicator_kwargs['name'] = name
        else:
            indicator_kwargs['name'] = f"{ioc_type.upper()}: {value}"
        
        if description:
            indicator_kwargs['description'] = description
        
        try:
            indicator = Indicator(**indicator_kwargs)
        except (InvalidValueError, MissingPropertiesError) as e:
            raise ValueError(f"Failed to create STIX Indicator: {str(e)}")
        
        sources = []
        if source:
            sources.append({
                'name': source.get('name', 'manual'),
                'timestamp': source.get('timestamp', datetime.utcnow().isoformat()),
                'metadata': source.get('metadata', {})
            })
        
        return cls(indicator, sources)
    
    @classmethod
    def from_pattern(cls, 
                     pattern: str,
                     labels: List[str] = None,
                     source: Dict = None,
                     name: str = None,
                     description: str = None) -> 'STIXIndicator':
        """
        Create a STIX Indicator from a raw STIX pattern.
        
        Args:
            pattern: STIX pattern string
            labels: List of labels/tags
            source: Source information dict
            name: Optional indicator name
            description: Optional description
        
        Returns:
            STIXIndicator instance
        """
        indicator_id = f"indicator--{uuid.uuid4()}"
        
        indicator_kwargs = {
            'id': indicator_id,
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': datetime.utcnow(),
        }
        
        if labels:
            indicator_kwargs['labels'] = labels
        
        if name:
            indicator_kwargs['name'] = name
        
        if description:
            indicator_kwargs['description'] = description
        
        try:
            indicator = Indicator(**indicator_kwargs)
        except (InvalidValueError, MissingPropertiesError) as e:
            raise ValueError(f"Failed to create STIX Indicator: {str(e)}")
        
        sources = []
        if source:
            sources.append({
                'name': source.get('name', 'manual'),
                'timestamp': source.get('timestamp', datetime.utcnow().isoformat()),
                'metadata': source.get('metadata', {})
            })
        
        return cls(indicator, sources)
    
    @classmethod
    def from_stix_dict(cls, data: Dict, sources: List[Dict] = None) -> 'STIXIndicator':
        """
        Create STIXIndicator from a dictionary.
        
        Args:
            data: STIX Indicator as dictionary
            sources: List of source information
        
        Returns:
            STIXIndicator instance
        """
        try:
            indicator = parse(data, allow_custom=True)
            if not isinstance(indicator, Indicator):
                raise ValueError("Parsed object is not a STIX Indicator")
            return cls(indicator, sources or [])
        except Exception as e:
            raise ValueError(f"Failed to parse STIX data: {str(e)}")
    
    def add_source(self, source: Dict):
        """Add a new source to this indicator (with deduplication)."""
        if source is None:
            source = {'name': 'unknown'}
        
        new_source = {
            'name': source.get('name', 'unknown'),
            'timestamp': source.get('timestamp', datetime.utcnow().isoformat()),
            'metadata': source.get('metadata', {})
        }
        
        # Check if this source already exists (avoid duplicates)
        source_exists = any(
            s.get('name') == new_source['name'] and 
            s.get('metadata') == new_source['metadata']
            for s in self.sources
        )
        
        if not source_exists:
            self.sources.append(new_source)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for storage.
        Returns STIX 2.1 compliant format with custom properties prefixed with x_.
        """
        indicator_dict = dict(self.indicator)
        
        # Convert datetime objects to ISO 8601 format with Z suffix (UTC)
        for key in ['created', 'modified', 'valid_from', 'valid_until']:
            if key in indicator_dict and indicator_dict[key]:
                if hasattr(indicator_dict[key], 'isoformat'):
                    iso_str = indicator_dict[key].isoformat()
                    # Ensure Z suffix for UTC timestamps
                    if iso_str.endswith('+00:00'):
                        iso_str = iso_str[:-6] + 'Z'
                    elif not iso_str.endswith('Z') and '+' not in iso_str:
                        iso_str = iso_str + 'Z'
                    indicator_dict[key] = iso_str
        
        # Ensure indicator_types exists (STIX 2.1 required for indicators)
        if 'indicator_types' not in indicator_dict or not indicator_dict.get('indicator_types'):
            indicator_dict['indicator_types'] = ['malicious-activity']
        
        # Add sources as external_references (STIX compliant)
        # Only include source_name and description, NOT metadata
        if self.sources:
            external_refs = []
            for source in self.sources:
                ref = {
                    'source_name': source.get('name', 'unknown'),
                }
                # Only add description if there's user metadata (user_id, username)
                if source.get('metadata', {}).get('user_id') or source.get('metadata', {}).get('username'):
                    ref['description'] = f"Added by {source.get('metadata', {}).get('username', 'unknown')} ({source.get('metadata', {}).get('user_id', 'unknown')})"
                external_refs.append(ref)
            if external_refs:
                indicator_dict['external_references'] = external_refs
        
        return indicator_dict
    
    def to_dict_with_metadata(self, ioc_type: str = None, ioc_value: str = None, 
                              pattern_hash: str = None, threat_level: str = None,
                              confidence: int = None, tlp: str = None, 
                              campaigns: List[str] = None, risk_score: int = None,
                              status: str = None, current_version: int = None,
                              user_id: str = None, username: str = None) -> Dict[str, Any]:
        """
        Convert to dictionary with STIX 2.1 custom properties (x_* prefix).
        Separates STIX-reserved fields from custom domain fields.
        
        Args:
            user_id: User ID who created/modified this indicator
            username: Username who created/modified this indicator
        """
        indicator_dict = self.to_dict()
        
        # Add custom properties with x_ prefix (STIX 2.1 compliant)
        custom_props = {}
        
        if ioc_type:
            custom_props['ioc_type'] = ioc_type
        if ioc_value:
            custom_props['ioc_value'] = ioc_value
        if pattern_hash:
            custom_props['pattern_hash'] = pattern_hash
        if threat_level:
            custom_props['threat_level'] = threat_level
        if tlp:
            custom_props['tlp'] = tlp
        if campaigns:
            custom_props['campaigns'] = campaigns
        if risk_score is not None:
            custom_props['risk_score'] = risk_score
        if status:
            custom_props['status'] = status
        if current_version is not None:
            custom_props['current_version'] = current_version
        
        # Add user information to metadata
        if user_id or username:
            custom_props['created_by'] = {
                'user_id': user_id,
                'username': username
            }
        
        # Add all custom properties under x_metadata (STIX 2.1 custom object)
        if custom_props:
            indicator_dict['x_metadata'] = custom_props
        
        # Ensure confidence is an integer 0-100 (STIX reserved field)
        if confidence is not None:
            indicator_dict['confidence'] = confidence
        
        return indicator_dict
    
    def to_stix(self) -> Indicator:
        """Return the underlying STIX Indicator."""
        return self.indicator
    
    def to_bundle(self) -> Bundle:
        """Create a STIX Bundle containing this indicator."""
        return Bundle(objects=[self.indicator])
    
    @property
    def pattern(self) -> str:
        """Get the STIX pattern."""
        return self.indicator.pattern
    
    @property
    def id(self) -> str:
        """Get the indicator ID."""
        return self.indicator.id
    
    @property
    def labels(self) -> List[str]:
        """Get the indicator labels."""
        return list(self.indicator.labels) if hasattr(self.indicator, 'labels') and self.indicator.labels else []
    
    @property
    def value(self) -> Optional[str]:
        """
        Extract the IOC value from the STIX pattern.
        Pattern format: [domain-name:value = 'example.com']
        Returns the extracted value or None.
        """
        import re
        if not self.indicator.pattern:
            return None
        
        # Try to extract value from pattern
        # Supports formats like: [domain-name:value = 'value'] or [file:hashes.MD5 = 'hash']
        match = re.search(r"['\"]([^'\"]+)['\"]", self.indicator.pattern)
        if match:
            return match.group(1)
        
        # If no quoted value found, try to extract from pattern
        # e.g., [autonomous-system:number = 1234]
        match = re.search(r"=\s*(\d+)", self.indicator.pattern)
        if match:
            return match.group(1)
        
        return None


class STIXBundle:
    """Wrapper for STIX 2.1 Bundle objects."""
    
    @classmethod
    def parse(cls, data: str) -> List[STIXIndicator]:
        """
        Parse a STIX Bundle from JSON string.
        
        Args:
            data: JSON string of STIX Bundle
        
        Returns:
            List of STIXIndicator objects
        """
        import json
        
        try:
            bundle_dict = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
        
        if bundle_dict.get('type') != 'bundle':
            raise ValueError("Not a valid STIX Bundle")
        
        indicators = []
        objects = bundle_dict.get('objects', [])
        
        for obj in objects:
            if obj.get('type') == 'indicator':
                try:
                    indicator = STIXIndicator.from_stix_dict(obj)
                    indicators.append(indicator)
                except ValueError as e:
                    # Log but continue processing other indicators
                    print(f"Warning: Skipping invalid indicator: {e}")
        
        return indicators
    
    @classmethod
    def create(cls, indicators: List[STIXIndicator]) -> Bundle:
        """
        Create a STIX Bundle from indicators.
        
        Args:
            indicators: List of STIXIndicator objects
        
        Returns:
            STIX Bundle object
        """
        stix_objects = [ind.to_stix() for ind in indicators]
        return Bundle(objects=stix_objects)
