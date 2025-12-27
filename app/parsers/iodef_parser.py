"""IODEF XML Parser."""

from typing import List, Dict
from lxml import etree

from app.utils.pattern_generator import PatternGenerator


class IODEFParser:
    """Parser for IODEF (Incident Object Description Exchange Format) XML."""
    
    # IODEF namespace
    NAMESPACES = {
        'iodef': 'urn:ietf:params:xml:ns:iodef-2.0',
        'iodef1': 'urn:ietf:params:xml:ns:iodef-1.0'
    }
    
    @classmethod
    def parse(cls, content: str) -> List[Dict]:
        """
        Parse IODEF XML content.
        
        Args:
            content: IODEF XML string
        
        Returns:
            List of IOC dictionaries with type, value, labels, etc.
        """
        try:
            root = etree.fromstring(content.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise ValueError(f'Invalid XML: {str(e)}')
        
        indicators = []
        
        # Find all Incident elements
        incidents = cls._find_elements(root, 'Incident')
        
        for incident in incidents:
            indicators.extend(cls._parse_incident(incident))
        
        # Also check for indicators directly at root level
        if not incidents:
            indicators.extend(cls._parse_incident(root))
        
        return indicators
    
    @classmethod
    def _parse_incident(cls, incident_elem) -> List[Dict]:
        """Parse a single Incident element."""
        indicators = []
        
        # Get incident metadata
        incident_id = ''
        description = ''
        
        # Find IncidentID
        for elem in cls._find_elements(incident_elem, 'IncidentID'):
            incident_id = elem.text or ''
            break
        
        # Find Description
        for elem in cls._find_elements(incident_elem, 'Description'):
            description = elem.text or ''
            break
        
        # Extract EventData elements
        event_data_elements = cls._find_elements(incident_elem, 'EventData')
        
        for event_data in event_data_elements:
            indicators.extend(cls._parse_event_data(event_data, incident_id, description))
        
        # Also look for indicators in other common locations
        # Flow elements
        for flow in cls._find_elements(incident_elem, 'Flow'):
            indicators.extend(cls._parse_flow(flow, incident_id, description))
        
        # Address elements directly
        for addr in cls._find_elements(incident_elem, 'Address'):
            indicator = cls._parse_address(addr, incident_id, description)
            if indicator:
                indicators.append(indicator)
        
        # Observable elements (IODEF 2.0)
        for obs in cls._find_elements(incident_elem, 'Observable'):
            indicators.extend(cls._parse_observable(obs, incident_id, description))
        
        return indicators
    
    @classmethod
    def _parse_event_data(cls, event_data, incident_id: str, description: str) -> List[Dict]:
        """Parse EventData element."""
        indicators = []
        
        # Find Flow elements
        for flow in cls._find_elements(event_data, 'Flow'):
            indicators.extend(cls._parse_flow(flow, incident_id, description))
        
        return indicators
    
    @classmethod
    def _parse_flow(cls, flow, incident_id: str, description: str) -> List[Dict]:
        """Parse Flow element."""
        indicators = []
        
        # Find System elements
        for system in cls._find_elements(flow, 'System'):
            # Find Node elements
            for node in cls._find_elements(system, 'Node'):
                # Find Address elements
                for addr in cls._find_elements(node, 'Address'):
                    indicator = cls._parse_address(addr, incident_id, description)
                    if indicator:
                        indicators.append(indicator)
                
                # Find NodeName (domain)
                for name in cls._find_elements(node, 'NodeName'):
                    value = (name.text or '').strip()
                    if value and PatternGenerator.validate_value('domain', value):
                        indicators.append({
                            'type': 'domain',
                            'value': value,
                            'labels': ['iodef'],
                            'name': f'domain: {value}',
                            'description': description,
                            'metadata': {'iodef_incident_id': incident_id}
                        })
        
        return indicators
    
    @classmethod
    def _parse_address(cls, addr_elem, incident_id: str, description: str) -> Dict:
        """Parse Address element."""
        value = (addr_elem.text or '').strip()
        if not value:
            return None
        
        # Get address category
        category = addr_elem.get('category', '').lower()
        
        # Determine IOC type
        ioc_type = None
        if category in ['ipv4-addr', 'ipv4']:
            ioc_type = 'ipv4'
        elif category == 'e-mail':
            ioc_type = 'email'
        else:
            # Auto-detect
            ioc_type = PatternGenerator.detect_type(value)
        
        if not ioc_type or not PatternGenerator.validate_value(ioc_type, value):
            return None
        
        return {
            'type': ioc_type,
            'value': value,
            'labels': ['iodef'],
            'name': f'{ioc_type}: {value}',
            'description': description,
            'metadata': {
                'iodef_incident_id': incident_id,
                'iodef_category': category
            }
        }
    
    @classmethod
    def _parse_observable(cls, obs_elem, incident_id: str, description: str) -> List[Dict]:
        """Parse Observable element (IODEF 2.0)."""
        indicators = []
        
        # Observable can contain various indicator types
        for elem in obs_elem.iter():
            tag = elem.tag.split('}')[-1].lower()
            value = (elem.text or '').strip()
            
            if not value:
                continue
            
            ioc_type = None
            if 'hash' in tag:
                # Detect hash type
                ioc_type = PatternGenerator.detect_type(value)
            elif 'ip' in tag or 'address' in tag:
                if PatternGenerator.validate_value('ipv4', value):
                    ioc_type = 'ipv4'
            elif 'domain' in tag or 'hostname' in tag:
                if PatternGenerator.validate_value('domain', value):
                    ioc_type = 'domain'
            elif 'email' in tag:
                if PatternGenerator.validate_value('email', value):
                    ioc_type = 'email'
            elif 'url' in tag or 'uri' in tag:
                if PatternGenerator.validate_value('url', value):
                    ioc_type = 'url'
            
            if ioc_type:
                indicators.append({
                    'type': ioc_type,
                    'value': value,
                    'labels': ['iodef'],
                    'name': f'{ioc_type}: {value}',
                    'description': description,
                    'metadata': {'iodef_incident_id': incident_id}
                })
        
        return indicators
    
    @classmethod
    def _find_elements(cls, root, local_name: str):
        """Find elements by local name, ignoring namespace."""
        elements = []
        
        for elem in root.iter():
            tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
            if tag == local_name:
                elements.append(elem)
        
        return elements
