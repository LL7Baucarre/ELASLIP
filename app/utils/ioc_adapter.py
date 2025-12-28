"""IOC Adapter for STIX 2.1 format normalization and backward compatibility."""

from typing import Dict, Any, List, Optional


def normalize_ioc_for_api(ioc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize IOC structure from new STIX 2.1 format to API-compatible format.
    
    Supports both old and new structure transparently:
    - New (STIX 2.1 compliant): x_threat_level, x_tlp, x_campaigns at root
    - Old: threat_level, tlp, campaigns in x_metadata or root
    
    Args:
        ioc: IOC document from Elasticsearch
        
    Returns:
        Normalized IOC with convenient field access
    """
    if not ioc:
        return ioc
    
    # Create a normalized copy
    normalized = dict(ioc)
    
    # Map x_* fields to convenient names for backward compatibility
    field_mappings = {
        'x_threat_level': 'threat_level',
        'x_tlp': 'tlp',
        'x_campaigns': 'campaigns',
        'x_risk_score': 'risk_score',
        'x_status': 'status',
        'x_ioc_type': 'ioc_type',
        'x_ioc_value': ['ioc_value', 'value'],  # Both ioc_value AND value as aliases
        'x_current_version': 'current_version',
        'x_pattern_hash': 'pattern_hash',
    }
    
    for x_field, convenient_names in field_mappings.items():
        if x_field in normalized:
            # Handle both single string and list of aliases
            if isinstance(convenient_names, list):
                for convenient_name in convenient_names:
                    if convenient_name not in normalized:
                        normalized[convenient_name] = normalized[x_field]
            else:
                if convenient_names not in normalized:
                    normalized[convenient_names] = normalized[x_field]
    
    return normalized


def normalize_ioc_list_for_api(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize a list of IOCs for API response.
    
    Args:
        iocs: List of IOC documents
        
    Returns:
        List of normalized IOCs
    """
    return [normalize_ioc_for_api(ioc) for ioc in iocs]
