"""API Template Model for mapping external API responses to STIX."""

from typing import Dict, Any, Optional, List
import logging
from jsonpath_ng import parse as jsonpath_parse
from jsonpath_ng.exceptions import JsonPathParserError

from app.utils.pattern_generator import PatternGenerator

logger = logging.getLogger(__name__)


class APITemplate:
    """
    Template for transforming external API responses to STIX format.
    
    Template format:
    {
        "ioc_type": "$.type",  # JSONPath to IOC type field
        "value": "$.data.hash",  # JSONPath to value field
        "labels": "$.tags",  # JSONPath to labels array
        "name": "$.name",  # Optional name
        "description": "$.description",  # Optional description
        "confidence": "$.confidence",  # Optional confidence score
        "extra_fields": {  # Extra fields to store in metadata
            "malicious_count": "$.stats.malicious",
            "vendor": "$.vendor"
        }
    }
    """
    
    def __init__(self, template: Dict[str, Any]):
        self.template = template
        self._compiled_paths = {}
        self._compile_paths()
    
    def _compile_paths(self):
        """Pre-compile JSONPath expressions."""
        for key, path in self.template.items():
            if isinstance(path, str) and path.startswith('$'):
                try:
                    self._compiled_paths[key] = jsonpath_parse(path)
                    logger.debug(f'[TEMPLATE] Compiled JSONPath for "{key}": {path}')
                except JsonPathParserError as e:
                    logger.warning(f'[TEMPLATE] Failed to parse JSONPath for "{key}": {path} - {str(e)}')
            elif isinstance(path, dict):
                # Handle nested mappings like extra_fields
                self._compiled_paths[key] = {}
                for subkey, subpath in path.items():
                    if isinstance(subpath, str) and subpath.startswith('$'):
                        try:
                            self._compiled_paths[key][subkey] = jsonpath_parse(subpath)
                            logger.debug(f'[TEMPLATE] Compiled JSONPath for "{key}.{subkey}": {subpath}')
                        except JsonPathParserError as e:
                            logger.warning(f'[TEMPLATE] Failed to parse JSONPath for "{key}.{subkey}": {subpath} - {str(e)}')
    
    def extract_value(self, data: Dict, path_key: str) -> Any:
        """Extract a value from data using compiled JSONPath."""
        if path_key not in self._compiled_paths:
            logger.info(f'[TEMPLATE] Path key "{path_key}" not found in compiled paths. Available: {list(self._compiled_paths.keys())}')
            return None
        
        compiled = self._compiled_paths[path_key]
        
        if isinstance(compiled, dict):
            # Nested mapping
            return {
                k: self._extract_single(data, v) 
                for k, v in compiled.items()
            }
        
        return self._extract_single(data, compiled)
    
    def _extract_single(self, data: Dict, compiled) -> Any:
        """Extract a single value using compiled path."""
        matches = compiled.find(data)
        logger.info(f'[TEMPLATE] JSONPath search found {len(matches) if matches else 0} matches: {[m.value for m in matches] if matches else "none"}')
        if not matches:
            return None
        
        if len(matches) == 1:
            return matches[0].value
        
        return [m.value for m in matches]
    
    def transform(self, response_data: Dict, original_value: str = None) -> Dict:
        """
        Transform API response to IOC format.
        
        Args:
            response_data: Raw API response
            original_value: Original IOC value that was queried
        
        Returns:
            Dictionary with IOC data ready for STIX conversion
        """
        logger.debug(f'[TEMPLATE] Transforming response with template keys: {list(self.template.keys())}')
        logger.debug(f'[TEMPLATE] Compiled paths keys: {list(self._compiled_paths.keys())}')
        
        result = {
            'raw_response': response_data,
            'transformed': {},
            'stix_indicator': None
        }
        
        # Extract basic fields
        ioc_type = self.extract_value(response_data, 'ioc_type')
        value = self.extract_value(response_data, 'value') or original_value
        labels = self.extract_value(response_data, 'labels') or []
        name = self.extract_value(response_data, 'name')
        description = self.extract_value(response_data, 'description')
        confidence = self.extract_value(response_data, 'confidence')
        extra_fields = self.extract_value(response_data, 'extra_fields') or {}
        
        logger.info(f'[TEMPLATE] Extracted - type: {ioc_type}, value: {value}, name: {name}, description: {description}')
        
        # Normalize labels
        if isinstance(labels, str):
            labels = [labels]
        labels = [str(l).lower() for l in labels if l]
        
        # Build final transformed data with all STIX fields
        transformed_data = {}
        
        # Always try to extract all STIX fields from both template and auto-detection
        stix_fields = {
            'threat_level': self.extract_value(response_data, 'threat_level'),
            'confidence': confidence or self.extract_value(response_data, 'confidence'),
            'tlp': self.extract_value(response_data, 'tlp'),
            'risk_score': self.extract_value(response_data, 'risk_score'),
            'severity': self.extract_value(response_data, 'severity'),
            'reputation': self.extract_value(response_data, 'reputation'),
            'malware_family': self.extract_value(response_data, 'malware_family'),
            'country': self.extract_value(response_data, 'country'),
            'asn': self.extract_value(response_data, 'asn'),
            'registrar': self.extract_value(response_data, 'registrar'),
            'last_seen': self.extract_value(response_data, 'last_seen'),
            'first_seen': self.extract_value(response_data, 'first_seen'),
            'detection_ratio': self.extract_value(response_data, 'detection_ratio'),
            'attributes': self.extract_value(response_data, 'attributes'),
            'metadata': self.extract_value(response_data, 'metadata'),
        }
        
        # Add all non-null STIX fields to transformed data
        for field, value in stix_fields.items():
            if value is not None:
                transformed_data[field] = value
        
        # If template is empty or no STIX values extracted, try to auto-detect common fields
        if not self.template or (not ioc_type and not name and not description and not transformed_data):
            logger.debug(f'[TEMPLATE] Template empty or no values extracted, using auto-detection')
            # Auto-detect common response fields
            if isinstance(response_data, dict):
                # Common field names across APIs for STIX fields
                common_field_mappings = {
                    'threat_level': ['threat_level', 'threat_types', 'threat', 'severity_level'],
                    'confidence': ['confidence', 'confidence_score', 'certainty'],
                    'tlp': ['tlp', 'tlp_level', 'traffic_light_protocol'],
                    'risk_score': ['risk_score', 'risk', 'score', 'risk_level'],
                    'severity': ['severity', 'severity_level', 'severity_score'],
                    'reputation': ['reputation', 'reputation_score', 'threat_score', 'malicious_score'],
                    'country': ['country', 'country_name', 'country_code', 'geo.country_name'],
                    'asn': ['asn', 'asn_number', 'as_number', 'autonomous_system'],
                    'registrar': ['registrar', 'registrar_name', 'domain_registrar'],
                    'last_seen': ['last_seen', 'last_analysis_date', 'last_modified', 'last_checked'],
                    'first_seen': ['first_seen', 'first_submission_date', 'first_checked', 'discovered_date'],
                    'detection_ratio': ['detection_ratio', 'detection_rate', 'detection_count', 'detections'],
                    'malware_family': ['malware_family', 'malware_name', 'family', 'malware_type'],
                    'isp': ['isp', 'isp_name', 'organization', 'org_name'],
                    'usage': ['usage', 'usage_type', 'usage_type_name'],
                }
                
                # Search for these common fields in response
                for api_field, possible_names in common_field_mappings.items():
                    if api_field not in transformed_data:  # Don't overwrite extracted values
                        for name_option in possible_names:
                            if name_option in response_data:
                                transformed_data[api_field] = response_data[name_option]
                                break
                
                # Store the entire response for inspection
                transformed_data['__api_response__'] = response_data
        
        result['transformed'] = {
            'ioc_type': ioc_type,
            'value': value,
            'labels': labels,
            'name': name,
            'description': description,
            **transformed_data  # Include all STIX fields
        }
        
        logger.info(f'[TEMPLATE] Final transformed result keys: {list(result["transformed"].keys())}')
        logger.info(f'[TEMPLATE] Final transformed result: {result["transformed"]}')
        # Try to create STIX indicator
        if value:
            # Detect type if not provided
            if not ioc_type:
                ioc_type = PatternGenerator.detect_type(value)
            
            if ioc_type and PatternGenerator.validate_value(ioc_type, value):
                try:
                    pattern = PatternGenerator.generate_pattern(ioc_type, value)
                    result['stix_indicator'] = {
                        'pattern': pattern,
                        'pattern_type': 'stix',
                        'ioc_type': ioc_type,
                        'value': value,
                        'labels': labels,
                        'name': name or f'{ioc_type}: {value}',
                        'description': description,
                        'metadata': extra_fields
                    }
                except ValueError:
                    pass
        
        return result
    
    @classmethod
    def validate_template(cls, template: Dict) -> List[str]:
        """
        Validate a template definition.
        
        Returns list of error messages (empty if valid).
        """
        errors = []
        
        if not isinstance(template, dict):
            return ['Template must be a dictionary']
        
        # Template can be empty - auto-detection will be used
        # Only validate JSONPath expressions that are provided
        for key, path in template.items():
            if isinstance(path, str) and path.startswith('$'):
                try:
                    jsonpath_parse(path)
                except JsonPathParserError as e:
                    errors.append(f'Invalid JSONPath for "{key}": {str(e)}')
            elif isinstance(path, dict):
                for subkey, subpath in path.items():
                    if isinstance(subpath, str) and subpath.startswith('$'):
                        try:
                            jsonpath_parse(subpath)
                        except JsonPathParserError as e:
                            errors.append(f'Invalid JSONPath for "{key}.{subkey}": {str(e)}')
        
        return errors


# Default templates for common APIs
DEFAULT_TEMPLATES = {
    'virustotal_file': {
        'description': 'VirusTotal file lookup',
        'template': {
            'ioc_type': None,  # Will be detected
            'value': '$.data.attributes.sha256',
            'labels': '$.data.attributes.tags',
            'name': '$.data.attributes.meaningful_name',
            'extra_fields': {
                'malicious': '$.data.attributes.last_analysis_stats.malicious',
                'suspicious': '$.data.attributes.last_analysis_stats.suspicious',
                'type_tag': '$.data.attributes.type_tag'
            }
        }
    },
    'virustotal_ip': {
        'description': 'VirusTotal IP lookup',
        'template': {
            'ioc_type': None,
            'value': '$.data.id',
            'labels': '$.data.attributes.tags',
            'extra_fields': {
                'country': '$.data.attributes.country',
                'as_owner': '$.data.attributes.as_owner',
                'malicious': '$.data.attributes.last_analysis_stats.malicious'
            }
        }
    },
    'abuseipdb': {
        'description': 'AbuseIPDB IP lookup',
        'template': {
            'ioc_type': None,
            'value': '$.data.ipAddress',
            'labels': None,
            'extra_fields': {
                'abuse_confidence': '$.data.abuseConfidenceScore',
                'country': '$.data.countryCode',
                'isp': '$.data.isp',
                'usage_type': '$.data.usageType',
                'total_reports': '$.data.totalReports'
            }
        }
    }
}
