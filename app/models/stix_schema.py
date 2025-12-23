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
        """Convert to dictionary for storage."""
        indicator_dict = dict(self.indicator)
        
        # Convert datetime objects to ISO format strings
        for key in ['created', 'modified', 'valid_from', 'valid_until']:
            if key in indicator_dict and indicator_dict[key]:
                if hasattr(indicator_dict[key], 'isoformat'):
                    indicator_dict[key] = indicator_dict[key].isoformat()
        
        return {
            **indicator_dict,
            'sources': self.sources
        }
    
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
