"""STIX 2.1 Schema and Models for IOC Manager."""

from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid

from stix2 import Indicator, Bundle, Relationship, parse
from stix2.exceptions import InvalidValueError, MissingPropertiesError


# STIX 2.1 Standard Relationship Types
# https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cqhkqvhnpstf
STIX_RELATIONSHIP_TYPES = [
    'indicates',         # Indicator points to malicious activity
    'uses',              # Uses a tool/technique
    'related-to',        # Generic relationship
    'derived-from',      # Derived from another object
    'duplicate-of',      # Duplicate of another object
    'based-on',          # Based on another object
    'targets',           # Targets a victim
    'attributed-to',     # Attributed to a threat actor
    'mitigates',         # Mitigates a vulnerability/threat
    'compromises',       # Compromises infrastructure
    'originates-from',   # Originates from a location
    'investigates',      # Investigates a threat
    'remediates',        # Remediates a threat
    'delivers',          # Delivers malware
    'drops',             # Drops malware
    'communicates-with', # Communicates with infrastructure
    'controls',          # Controls infrastructure
    'exploits',          # Exploits a vulnerability
]


class STIXRelationship:
    """
    Wrapper for STIX 2.1 Relationship objects (SRO).
    
    A STIX Relationship is used to link two STIX Domain Objects (SDOs) together.
    This class provides methods to create, validate, and convert relationship objects
    following the STIX 2.1 specification.
    """
    
    def __init__(self, relationship: Relationship):
        self.relationship = relationship
    
    @classmethod
    def create(cls,
               source_ref: str,
               target_ref: str,
               relationship_type: str,
               description: str = None,
               start_time: datetime = None,
               stop_time: datetime = None,
               created_by_ref: str = None,
               external_references: List[Dict] = None) -> 'STIXRelationship':
        """
        Create a new STIX 2.1 Relationship.
        
        Args:
            source_ref: STIX ID of the source object (e.g., indicator--uuid)
            target_ref: STIX ID of the target object (e.g., indicator--uuid)
            relationship_type: Type of relationship (must be STIX-standard)
            description: Optional description of the relationship
            start_time: Optional start time of the relationship
            stop_time: Optional stop time of the relationship
            created_by_ref: Optional STIX ID of the identity that created this
            external_references: Optional list of external references
        
        Returns:
            STIXRelationship instance
        
        Raises:
            ValueError: If relationship_type is not a valid STIX relationship type
        """
        # Validate relationship type
        if relationship_type not in STIX_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Invalid relationship_type '{relationship_type}'. "
                f"Must be one of: {', '.join(STIX_RELATIONSHIP_TYPES)}"
            )
        
        # Generate STIX ID
        relationship_id = f"relationship--{uuid.uuid4()}"
        
        # Build relationship kwargs
        rel_kwargs = {
            'id': relationship_id,
            'source_ref': source_ref,
            'target_ref': target_ref,
            'relationship_type': relationship_type,
        }
        
        if description:
            rel_kwargs['description'] = description
        
        if start_time:
            rel_kwargs['start_time'] = start_time
        
        if stop_time:
            rel_kwargs['stop_time'] = stop_time
        
        if created_by_ref:
            rel_kwargs['created_by_ref'] = created_by_ref
        
        if external_references:
            rel_kwargs['external_references'] = external_references
        
        try:
            relationship = Relationship(**rel_kwargs)
        except (InvalidValueError, MissingPropertiesError) as e:
            raise ValueError(f"Failed to create STIX Relationship: {str(e)}")
        
        return cls(relationship)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'STIXRelationship':
        """
        Create STIXRelationship from a dictionary.
        
        Args:
            data: STIX Relationship as dictionary
        
        Returns:
            STIXRelationship instance
        """
        try:
            relationship = parse(data, allow_custom=True)
            if not isinstance(relationship, Relationship):
                raise ValueError("Parsed object is not a STIX Relationship")
            return cls(relationship)
        except Exception as e:
            raise ValueError(f"Failed to parse STIX Relationship: {str(e)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for storage.
        Returns STIX 2.1 compliant format.
        """
        rel_dict = dict(self.relationship)
        
        # Convert datetime objects to ISO 8601 format with Z suffix (UTC)
        for key in ['created', 'modified', 'start_time', 'stop_time']:
            if key in rel_dict and rel_dict[key]:
                if hasattr(rel_dict[key], 'isoformat'):
                    iso_str = rel_dict[key].isoformat()
                    # Ensure Z suffix for UTC timestamps
                    if iso_str.endswith('+00:00'):
                        iso_str = iso_str[:-6] + 'Z'
                    elif not iso_str.endswith('Z') and '+' not in iso_str:
                        iso_str = iso_str + 'Z'
                    rel_dict[key] = iso_str
        
        return rel_dict
    
    def to_dict_with_metadata(self, user_id: str = None, username: str = None) -> Dict[str, Any]:
        """
        Convert to dictionary with custom metadata for ELASLIP storage.
        
        Args:
            user_id: User ID who created this relationship
            username: Username who created this relationship
        
        Returns:
            Dictionary with STIX relationship and custom metadata
        """
        rel_dict = self.to_dict()
        
        # Add custom ELASLIP metadata (x_ prefix per STIX 2.1)
        if user_id:
            rel_dict['x_elaslip_created_by_user_id'] = user_id
        if username:
            rel_dict['x_elaslip_created_by_username'] = username
        
        return rel_dict
    
    def to_stix(self) -> Relationship:
        """Return the underlying STIX Relationship."""
        return self.relationship
    
    @property
    def id(self) -> str:
        """Get the relationship ID."""
        return self.relationship.id
    
    @property
    def source_ref(self) -> str:
        """Get the source reference."""
        return self.relationship.source_ref
    
    @property
    def target_ref(self) -> str:
        """Get the target reference."""
        return self.relationship.target_ref
    
    @property
    def relationship_type(self) -> str:
        """Get the relationship type."""
        return self.relationship.relationship_type
    
    @classmethod
    def get_valid_types(cls) -> List[str]:
        """Return list of valid STIX relationship types."""
        return STIX_RELATIONSHIP_TYPES.copy()


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
        
        # Don't add sources or external_references to root level - keep them in x_metadata only
        # (external_references should only be added if explicitly set, not auto-generated from sources)
        
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
        
        # Always add ioc_type and ioc_value if provided (even if None/empty)
        if ioc_type is not None:
            custom_props['ioc_type'] = ioc_type
        if ioc_value is not None:
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
        
        # Add sources if available
        if self.sources:
            custom_props['sources'] = self.sources
        
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
    
    # Supported STIX Domain Objects (SDO) types
    SUPPORTED_SDO_TYPES = [
        'indicator',      # IOCs (handled separately)
        'malware',        # Malware information
        'threat-actor',   # Threat actor profiles
        'attack-pattern', # Attack patterns (MITRE ATT&CK)
        'campaign',       # Campaigns
        'tool',           # Tools used by threat actors
        'vulnerability',  # Vulnerabilities
        'infrastructure', # Infrastructure
        'intrusion-set',  # Intrusion sets
        'identity',       # Identity objects
        'location',       # Geographic locations
        'malware-analysis', # Malware analysis results
        'note',           # Notes
        'observed-data',  # Observed data
        'opinion',        # Opinions
        'report',         # Reports
        'course-of-action', # Mitigations
        'grouping',       # Groupings
    ]
    
    @classmethod
    def parse(cls, data: str) -> List['STIXIndicator']:
        """
        Parse STIX objects from JSON string.
        Handles both individual STIX Indicators and STIX Bundles.
        
        Args:
            data: JSON string of STIX Indicator or STIX Bundle
        
        Returns:
            List of STIXIndicator objects
        """
        import json
        
        try:
            stix_dict = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
        
        indicators = []
        stix_type = stix_dict.get('type')
        
        if stix_type == 'bundle':
            # Handle STIX Bundle
            objects = stix_dict.get('objects', [])
            for obj in objects:
                if obj.get('type') == 'indicator':
                    try:
                        indicator = STIXIndicator.from_stix_dict(obj)
                        indicators.append(indicator)
                    except ValueError as e:
                        # Log but continue processing other indicators
                        import logging
                        logging.getLogger(__name__).warning("Skipping invalid indicator: %s", e)
        elif stix_type == 'indicator':
            # Handle single STIX Indicator
            try:
                indicator = STIXIndicator.from_stix_dict(stix_dict)
                indicators.append(indicator)
            except ValueError as e:
                raise ValueError(f"Failed to parse STIX Indicator: {str(e)}")
        else:
            raise ValueError(f"Unsupported STIX object type: {stix_type}. Expected 'bundle' or 'indicator'")
        
        if not indicators:
            raise ValueError("No valid indicators found in STIX data")
        
        return indicators
    
    @classmethod
    def parse_full(cls, data: str) -> Dict[str, List]:
        """
        Parse ALL STIX objects from JSON string (indicators, relationships, malware, etc.).
        
        Args:
            data: JSON string of STIX Indicator, Bundle, or other SDO
        
        Returns:
            Dictionary with keys:
                - 'indicators': List of STIXIndicator objects
                - 'relationships': List of relationship dicts
                - 'objects': List of other SDO dicts (malware, threat-actor, etc.)
        """
        import json
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            stix_dict = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
        
        result = {
            'indicators': [],
            'relationships': [],
            'objects': []
        }
        
        stix_type = stix_dict.get('type')
        
        if stix_type == 'bundle':
            # Handle STIX Bundle with multiple objects
            objects = stix_dict.get('objects', [])
            for obj in objects:
                obj_type = obj.get('type')
                
                if obj_type == 'indicator':
                    try:
                        indicator = STIXIndicator.from_stix_dict(obj)
                        result['indicators'].append(indicator)
                    except ValueError as e:
                        logger.warning("Skipping invalid indicator: %s", e)
                
                elif obj_type == 'relationship':
                    # Validate and store relationship
                    if cls._validate_relationship(obj):
                        result['relationships'].append(obj)
                    else:
                        logger.warning("Skipping invalid relationship: missing required fields")
                
                elif obj_type in cls.SUPPORTED_SDO_TYPES:
                    # Store other SDO types (malware, threat-actor, etc.)
                    result['objects'].append(obj)
                
                else:
                    logger.info("Skipping unsupported STIX object type: %s", obj_type)
        
        elif stix_type == 'indicator':
            # Handle single STIX Indicator
            try:
                indicator = STIXIndicator.from_stix_dict(stix_dict)
                result['indicators'].append(indicator)
            except ValueError as e:
                raise ValueError(f"Failed to parse STIX Indicator: {str(e)}")
        
        elif stix_type == 'relationship':
            # Handle single relationship
            if cls._validate_relationship(stix_dict):
                result['relationships'].append(stix_dict)
            else:
                raise ValueError("Invalid relationship: missing required fields (source_ref, target_ref, relationship_type)")
        
        elif stix_type in cls.SUPPORTED_SDO_TYPES:
            # Handle single SDO
            result['objects'].append(stix_dict)
        
        else:
            raise ValueError(f"Unsupported STIX object type: {stix_type}")
        
        return result
    
    @classmethod
    def _validate_relationship(cls, rel: Dict) -> bool:
        """Validate that a relationship has required fields."""
        return all([
            rel.get('source_ref'),
            rel.get('target_ref'),
            rel.get('relationship_type')
        ])
    
    @classmethod
    def create(cls, indicators: List['STIXIndicator']) -> Bundle:
        """
        Create a STIX Bundle from indicators.
        
        Args:
            indicators: List of STIXIndicator objects
        
        Returns:
            STIX Bundle object
        """
        stix_objects = [ind.to_stix() for ind in indicators]
        return Bundle(objects=stix_objects)
