"""MISP JSON Parser."""

import json
from typing import List, Dict

from app.utils.pattern_generator import PatternGenerator


class MISPParser:
    """Parser for MISP JSON format."""
    
    # Mapping of MISP types to our IOC types
    TYPE_MAPPING = {
        'md5': 'md5',
        'sha1': 'sha1',
        'sha256': 'sha256',
        'ip-src': 'ipv4',
        'ip-dst': 'ipv4',
        'ip': 'ipv4',
        'domain': 'domain',
        'hostname': 'domain',
        'email-src': 'email',
        'email-dst': 'email',
        'email': 'email',
        'url': 'url',
        'link': 'url'
    }
    
    @classmethod
    def parse(cls, content: str) -> List[Dict]:
        """
        Parse MISP JSON content.
        
        Args:
            content: MISP JSON string
        
        Returns:
            List of IOC dictionaries with type, value, labels, etc.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f'Invalid JSON: {str(e)}')
        
        indicators = []
        
        # Handle MISP event format
        if 'Event' in data:
            event = data['Event']
            attributes = event.get('Attribute', [])
            event_tags = cls._extract_tags(event.get('Tag', []))
            event_info = event.get('info', '')
        elif 'response' in data:
            # Handle API response format
            for item in data['response']:
                if 'Event' in item:
                    event = item['Event']
                    attributes = event.get('Attribute', [])
                    event_tags = cls._extract_tags(event.get('Tag', []))
                    event_info = event.get('info', '')
                    indicators.extend(cls._parse_attributes(attributes, event_tags, event_info))
            return indicators
        elif isinstance(data, list):
            # Handle list of attributes
            attributes = data
            event_tags = []
            event_info = ''
        else:
            # Handle single event or attributes
            attributes = data.get('Attribute', [])
            event_tags = cls._extract_tags(data.get('Tag', []))
            event_info = data.get('info', '')
        
        indicators.extend(cls._parse_attributes(attributes, event_tags, event_info))
        
        return indicators
    
    @classmethod
    def _parse_attributes(cls, attributes: List[Dict], event_tags: List[str], 
                          event_info: str) -> List[Dict]:
        """Parse MISP attributes into IOC dictionaries."""
        indicators = []
        
        for attr in attributes:
            misp_type = attr.get('type', '').lower()
            value = attr.get('value', '').strip()
            
            if not value:
                continue
            
            # Map MISP type to our type
            ioc_type = cls.TYPE_MAPPING.get(misp_type)
            
            if not ioc_type:
                # Try to auto-detect
                ioc_type = PatternGenerator.detect_type(value)
            
            if not ioc_type:
                continue
            
            # Validate value
            if not PatternGenerator.validate_value(ioc_type, value):
                continue
            
            # Extract attribute tags
            attr_tags = cls._extract_tags(attr.get('Tag', []))
            labels = list(set(event_tags + attr_tags))
            
            # Add category as label if present
            category = attr.get('category')
            if category:
                labels.append(category.lower().replace(' ', '-'))
            
            indicator = {
                'type': ioc_type,
                'value': value,
                'labels': labels,
                'name': attr.get('comment') or f'{ioc_type}: {value}',
                'description': event_info if event_info else attr.get('comment'),
                'metadata': {
                    'misp_uuid': attr.get('uuid'),
                    'misp_category': category,
                    'misp_to_ids': attr.get('to_ids'),
                    'misp_timestamp': attr.get('timestamp')
                }
            }
            
            indicators.append(indicator)
        
        return indicators
    
    @classmethod
    def _extract_tags(cls, tags: List[Dict]) -> List[str]:
        """Extract tag names from MISP tag objects."""
        result = []
        for tag in tags:
            if isinstance(tag, dict):
                name = tag.get('name', '')
            else:
                name = str(tag)
            
            if name:
                # Clean up tag name
                name = name.strip().lower()
                # Remove common prefixes
                for prefix in ['misp-galaxy:', 'tlp:', 'admiralty-scale:']:
                    if name.startswith(prefix):
                        name = name[len(prefix):]
                result.append(name)
        
        return result
