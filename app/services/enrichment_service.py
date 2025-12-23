"""Enrichment Service for external API integration."""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

import requests
from redis import Redis

from app.services.elasticsearch_service import ElasticsearchService
from app.services.encryption_service import EncryptionService
from app.models.api_template import APITemplate
from app.utils.pattern_generator import PatternGenerator


class EnrichmentService:
    """Service for enriching IOCs using external APIs."""
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.redis = Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        self.cache_ttl = int(os.getenv('ENRICHMENT_CACHE_TTL', 3600))
        self.encryption = EncryptionService()
    
    def enrich_value(self, value: str, ioc_type: str = None, 
                     user_id: str = None) -> List[Dict]:
        """
        Enrich an IOC value using all enabled external APIs.
        
        Args:
            value: IOC value to enrich
            ioc_type: Type of IOC (optional, will auto-detect)
            user_id: User ID to get API configs for
        
        Returns:
            List of enrichment results from each API
        """
        if not ioc_type:
            ioc_type = PatternGenerator.detect_type(value)
        
        results = []
        
        # Get all enabled API configs for user
        if user_id:
            configs = self._get_user_api_configs(user_id)
        else:
            configs = []
        
        for config in configs:
            if not config.get('enabled', True):
                continue
            
            try:
                result = self.call_external_api(config, value, ioc_type)
                result['api_name'] = config['name']
                result['api_id'] = config['id']
                results.append(result)
            except Exception as e:
                results.append({
                    'api_name': config['name'],
                    'api_id': config['id'],
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def enrich_value_with_apis(self, value: str, ioc_type: str = None, 
                               user_id: str = None, api_ids: List[str] = None) -> List[Dict]:
        """
        Enrich an IOC value using specific external APIs.
        
        Args:
            value: IOC value to enrich
            ioc_type: Type of IOC (optional, will auto-detect)
            user_id: User ID to get API configs for
            api_ids: List of specific API IDs to use
        
        Returns:
            List of enrichment results from requested APIs
        """
        if not ioc_type:
            ioc_type = PatternGenerator.detect_type(value)
        
        results = []
        
        if not user_id or not api_ids:
            return results
        
        # Get specific API configs
        for api_id in api_ids:
            try:
                config = self.es.get('api_configs', api_id)
                if not config:
                    continue
                
                config_data = config['_source']
                config_data['id'] = api_id
                
                # Check if API belongs to user and is enabled
                if config_data.get('user_id') != user_id:
                    continue
                
                if not config_data.get('enabled', True):
                    continue
                
                try:
                    result = self.call_external_api(config_data, value, ioc_type)
                    result['api_name'] = config_data['name']
                    result['api_id'] = api_id
                    results.append(result)
                except Exception as e:
                    results.append({
                        'api_name': config_data['name'],
                        'api_id': api_id,
                        'success': False,
                        'error': str(e)
                    })
            except Exception as e:
                results.append({
                    'api_name': f'API {api_id}',
                    'api_id': api_id,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def call_external_api(self, config: Dict, value: str, 
                          ioc_type: str = None) -> Dict:
        """
        Call an external API and transform the response.
        
        Args:
            config: API configuration
            value: IOC value to query
            ioc_type: Type of IOC
        
        Returns:
            Dictionary with raw response and transformed data
        """
        # Get config ID (may not exist for new configs being tested)
        config_id = config.get('id') or config.get('url', 'test')
        
        # Check cache first (only if config has an id)
        if config.get('id'):
            cache_key = self._get_cache_key(config['id'], value)
            cached = self._get_from_cache(cache_key)
            if cached:
                cached['from_cache'] = True
                return cached
        
        # Build request URL (replace {value} placeholder)
        # Support both 'url' and 'url_template' keys
        url = config.get('url') or config.get('url_template')
        if not url:
            raise ValueError('url or url_template is required')
            
        url = url.replace('{value}', value)
        
        # Prepare headers
        headers = config.get('headers', {}).copy()
        
        # Add auth if configured
        auth_type = config.get('auth_type', 'none')
        auth_token = config.get('auth_token')
        
        # Decrypt auth token if encrypted
        if auth_token:
            auth_token = self.encryption.decrypt_if_needed(auth_token)
        
        if auth_type == 'bearer' and auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        elif auth_type == 'header' and auth_token:
            # Token is already in headers or use default header
            if 'X-API-Key' not in headers and 'x-apikey' not in headers:
                headers['X-API-Key'] = auth_token
        
        # Make request
        method = config.get('method', 'GET').upper()
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, headers=headers, 
                                        json={'value': value}, timeout=30)
            else:
                raise ValueError(f'Unsupported HTTP method: {method}')
            
            response.raise_for_status()
            response_data = response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f'API request failed: {str(e)}')
        except json.JSONDecodeError:
            raise Exception('API returned invalid JSON')
        
        # Transform response using template
        template_config = config.get('template', {}) or config.get('response_template', {})
        template = APITemplate(template_config)
        result = template.transform(response_data, value)
        result['success'] = True
        result['from_cache'] = False
        
        # Cache the result (only if config has an id)
        if config.get('id'):
            self._save_to_cache(cache_key, result, config['id'], value)
        
        return result
    
    def _get_user_api_configs(self, user_id: str) -> List[Dict]:
        """Get all API configurations for a user."""
        result = self.es.search('api_configs', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'user_id': user_id}},
                        {'term': {'enabled': True}}
                    ]
                }
            },
            'size': 50
        })
        
        configs = []
        for hit in result['hits']['hits']:
            config = hit['_source']
            config['id'] = hit['_id']
            configs.append(config)
        
        return configs
    
    def _get_cache_key(self, config_id: str, value: str) -> str:
        """Generate cache key for an enrichment result."""
        return f"enrich:{config_id}:{hashlib.md5(value.encode()).hexdigest()}"
    
    def _get_from_cache(self, cache_key: str) -> Optional[Dict]:
        """Get result from Redis cache."""
        try:
            data = self.redis.get(cache_key)
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None
    
    def _save_to_cache(self, cache_key: str, result: Dict, 
                       config_id: str, value: str):
        """Save result to Redis cache and Elasticsearch."""
        try:
            # Save to Redis with TTL
            self.redis.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(result, default=str)
            )
            
            # Also save to Elasticsearch for persistence
            cache_id = hashlib.md5(cache_key.encode()).hexdigest()
            self.es.index('enrichment_cache', cache_id, {
                'id': cache_id,
                'ioc_value': value,
                'api_config_id': config_id,
                'result': result,
                'cached_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(seconds=self.cache_ttl)).isoformat()
            })
        except Exception:
            # Cache failures shouldn't break enrichment
            pass
    
    def clear_cache(self, config_id: str = None, value: str = None):
        """Clear enrichment cache."""
        if config_id and value:
            # Clear specific cache entry
            cache_key = self._get_cache_key(config_id, value)
            self.redis.delete(cache_key)
        elif config_id:
            # Clear all cache for a config
            pattern = f"enrich:{config_id}:*"
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
