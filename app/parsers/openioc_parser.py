"""OpenIOC XML Parser."""

from typing import List, Dict
from lxml import etree

from app.utils.pattern_generator import PatternGenerator


class OpenIOCParser:
    """Parser for OpenIOC XML format."""
    
    # Mapping of OpenIOC search terms to our IOC types
    SEARCH_TERM_MAPPING = {
        'FileItem/Md5sum': 'md5',
        'FileItem/Sha1sum': 'sha1',
        'FileItem/Sha256sum': 'sha256',
        'PortItem/remoteIP': 'ipv4',
        'Network/DNS': 'domain',
        'DnsEntryItem/Host': 'domain',
        'DnsEntryItem/RecordName': 'domain',
        'Email/From': 'email',
        'Email/To': 'email',
        'UrlHistoryItem/URL': 'url',
        'FileDownloadHistoryItem/SourceURL': 'url'
    }
    
    # Namespaces used in OpenIOC
    NAMESPACES = {
        'ioc': 'http://schemas.mandiant.com/2010/ioc',
        'ioc-tr': 'http://schemas.mandiant.com/2010/ioc/TR/'
    }
    
    @classmethod
    def parse(cls, content: str) -> List[Dict]:
        """
        Parse OpenIOC XML content.
        
        Args:
            content: OpenIOC XML string
        
        Returns:
            List of IOC dictionaries with type, value, labels, etc.
        """
        try:
            root = etree.fromstring(content.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise ValueError(f'Invalid XML: {str(e)}')
        
        indicators = []
        
        # Try to find IOC definition
        # OpenIOC can have different root elements
        if root.tag.endswith('ioc') or 'ioc' in root.tag.lower():
            indicators.extend(cls._parse_ioc_element(root))
        elif root.tag.endswith('iocs'):
            # Multiple IOCs
            for ioc_elem in root:
                if 'ioc' in ioc_elem.tag.lower():
                    indicators.extend(cls._parse_ioc_element(ioc_elem))
        else:
            # Try to find IndicatorItem elements anywhere
            indicators.extend(cls._parse_ioc_element(root))
        
        return indicators
    
    @classmethod
    def _parse_ioc_element(cls, ioc_elem) -> List[Dict]:
        """Parse a single IOC element."""
        indicators = []
        
        # Get IOC metadata
        ioc_id = ioc_elem.get('id', '')
        
        # Find description
        description = ''
        for desc_elem in ioc_elem.iter():
            if desc_elem.tag.endswith('description') or desc_elem.tag.endswith('short_description'):
                description = desc_elem.text or ''
                break
        
        # Find all IndicatorItem elements
        for item in ioc_elem.iter():
            if not item.tag.endswith('IndicatorItem'):
                continue
            
            # Get condition and search term
            context = item.find('.//*[local-name()="Context"]')
            content_elem = item.find('.//*[local-name()="Content"]')
            
            if context is None or content_elem is None:
                continue
            
            search_term = context.get('search', '')
            value = (content_elem.text or '').strip()
            
            if not value:
                continue
            
            # Map search term to IOC type
            ioc_type = None
            for term, mapped_type in cls.SEARCH_TERM_MAPPING.items():
                if term.lower() in search_term.lower():
                    ioc_type = mapped_type
                    break
            
            if not ioc_type:
                # Try to auto-detect
                ioc_type = PatternGenerator.detect_type(value)
            
            if not ioc_type:
                continue
            
            # Validate value
            if not PatternGenerator.validate_value(ioc_type, value):
                continue
            
            indicator = {
                'type': ioc_type,
                'value': value,
                'labels': ['openioc'],
                'name': f'{ioc_type}: {value}',
                'description': description,
                'metadata': {
                    'openioc_id': ioc_id,
                    'openioc_search_term': search_term
                }
            }
            
            indicators.append(indicator)
        
        return indicators
