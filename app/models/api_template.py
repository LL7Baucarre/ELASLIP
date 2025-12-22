"""API Template Model for mapping external API responses to STIX."""

from typing import Dict, Any, Optional, List
from jsonpath_ng import parse as jsonpath_parse
from jsonpath_ng.exceptions import JsonPathParserError

from app.utils.pattern_generator import PatternGenerator


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
                except JsonPathParserError:
                    pass
            elif isinstance(path, dict):
                # Handle nested mappings like extra_fields
                self._compiled_paths[key] = {}
                for subkey, subpath in path.items():
                    if isinstance(subpath, str) and subpath.startswith('$'):
                        try:
                            self._compiled_paths[key][subkey] = jsonpath_parse(subpath)
                        except JsonPathParserError:
                            pass
    
    def extract_value(self, data: Dict, path_key: str) -> Any:
        """Extract a value from data using compiled JSONPath."""
        if path_key not in self._compiled_paths:
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
        
        # Normalize labels
        if isinstance(labels, str):
            labels = [labels]
        labels = [str(l).lower() for l in labels if l]
        
        result['transformed'] = {
            'ioc_type': ioc_type,
            'value': value,
            'labels': labels,
            'name': name,
            'description': description,
            'confidence': confidence,
            'extra_fields': extra_fields
        }
        
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
        
        # Check required path
        if 'value' not in template and 'ioc_type' not in template:
            errors.append('Template should have at least "value" or "ioc_type" mapping')
        
        # Validate JSONPath expressions
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
