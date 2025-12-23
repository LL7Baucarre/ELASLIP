"""External API Configuration Routes."""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.services.enrichment_service import EnrichmentService
from app.services.encryption_service import EncryptionService

api_config_bp = Blueprint('api_config', __name__)


@api_config_bp.route('', methods=['GET'])
@login_or_api_key_required
def list_api_configs():
    """List all API configurations for current user."""
    es = ElasticsearchService()
    
    result = es.search('api_configs', {
        'query': {'term': {'user_id': g.current_user.id}},
        'size': 100
    })
    
    configs = []
    for hit in result['hits']['hits']:
        config = hit['_source']
        config_id = hit['_id']
        
        # Map field names for backward compatibility with frontend
        mapped_config = {
            'id': config_id,
            'name': config.get('name', ''),
            'description': config.get('description', ''),
            'url': config.get('url', ''),
            'url_template': config.get('url', ''),  # Alias for UI
            'method': config.get('method', 'GET'),
            'headers': config.get('headers', {}),
            'post_body': config.get('post_body'),  # Include POST body
            'template': config.get('template', {}),
            'response_template': config.get('template', {}),  # Alias for UI
            'enabled': config.get('enabled', True),
            'is_enabled': config.get('enabled', True),  # Alias for UI
            'ioc_types': config.get('ioc_types', []),
            'timeout': config.get('timeout', 30),
            'created_at': config.get('created_at'),
            'updated_at': config.get('updated_at'),
            'auth_token': '***' if config.get('auth_token') else None
        }
        configs.append(mapped_config)
    
    return jsonify({'configs': configs})


@api_config_bp.route('', methods=['POST'])
@login_or_api_key_required
def create_api_config():
    """
    Create a new external API configuration.
    
    Expected JSON body:
    {
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/api/v3/files/{value}",
        "method": "GET",
        "headers": {"x-apikey": "your-api-key"},
        "auth_type": "header",
        "auth_token": null,
        "template": {
            "ioc_type": "$.data.type",
            "value": "$.data.attributes.sha256",
            "labels": "$.data.attributes.tags",
            "malicious": "$.data.attributes.last_analysis_stats.malicious"
        },
        "enabled": true
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Support both 'url' and 'url_template' field names
    api_url = data.get('url') or data.get('url_template')
    
    required_fields = ['name', api_url]
    if not data.get('name'):
        return jsonify({'error': 'name is required'}), 400
    if not api_url:
        return jsonify({'error': 'url or url_template is required'}), 400
    
    es = ElasticsearchService()
    config_id = secrets.token_hex(16)
    
    # Validate template if provided
    from app.models.api_template import APITemplate
    template_to_validate = data.get('template') or data.get('response_template') or {}
    if template_to_validate:
        errors = APITemplate.validate_template(template_to_validate)
        if errors:
            return jsonify({'error': 'Invalid template: ' + '; '.join(errors)}), 400
    
    config = {
        'id': config_id,
        'user_id': g.current_user.id,
        'name': data['name'],
        'description': data.get('description', ''),
        'url': api_url,
        'method': data.get('method', 'GET').upper(),
        'headers': data.get('headers', {}),
        'post_body': data.get('post_body'),  # Include POST body
        'auth_type': data.get('auth_type', 'none'),
        'auth_token': EncryptionService().encrypt(data.get('auth_token')) if data.get('auth_token') else None,
        'template': data.get('template', {}) or data.get('response_template', {}),
        'enabled': data.get('enabled', True) or data.get('is_enabled', True),
        'ioc_types': data.get('ioc_types', []),
        'timeout': data.get('timeout', 30),
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    
    es.index('api_configs', config_id, config)
    
    # Don't return auth token
    response_config = config.copy()
    if response_config.get('auth_token'):
        response_config['auth_token'] = '***'
    
    return jsonify({
        'message': 'API configuration created',
        'config': response_config
    }), 201


@api_config_bp.route('/<config_id>', methods=['GET'])
@login_or_api_key_required
def get_api_config(config_id):
    """Get a single API configuration."""
    es = ElasticsearchService()
    
    result = es.get('api_configs', config_id)
    
    if not result:
        return jsonify({'error': 'API configuration not found'}), 404
    
    config = result['_source']
    
    if config['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    config['id'] = config_id
    if config.get('auth_token'):
        config['auth_token'] = '***'
    
    # Map field names for backward compatibility with frontend
    response = {
        'id': config_id,
        'name': config.get('name', ''),
        'description': config.get('description', ''),
        'url': config.get('url', ''),
        'url_template': config.get('url', ''),  # Alias for UI
        'method': config.get('method', 'GET'),
        'headers': config.get('headers', {}),
        'post_body': config.get('post_body'),  # Include POST body
        'template': config.get('template', {}),
        'response_template': config.get('template', {}),  # Alias for UI
        'enabled': config.get('enabled', True),
        'is_enabled': config.get('enabled', True),  # Alias for UI
        'ioc_types': config.get('ioc_types', []),
        'timeout': config.get('timeout', 30),
        'created_at': config.get('created_at'),
        'updated_at': config.get('updated_at'),
        'auth_token': config.get('auth_token', '***')
    }
    
    return jsonify(response)


@api_config_bp.route('/<config_id>', methods=['PUT'])
@login_or_api_key_required
def update_api_config(config_id):
    """Update an API configuration."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    es = ElasticsearchService()
    
    result = es.get('api_configs', config_id)
    
    if not result:
        return jsonify({'error': 'API configuration not found'}), 404
    
    config = result['_source']
    
    if config['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Update allowed fields
    # Support both 'url' and 'url_template' field names, and 'template'/'response_template'
    allowed_fields = ['name', 'description', 'url', 'url_template', 'method', 'headers', 'post_body',
                      'auth_type', 'auth_token', 'template', 'response_template', 'enabled', 'is_enabled',
                      'ioc_types', 'timeout']
    
    # Validate template if provided
    from app.models.api_template import APITemplate
    template_to_validate = data.get('template') or data.get('response_template') or {}
    if template_to_validate:
        errors = APITemplate.validate_template(template_to_validate)
        if errors:
            return jsonify({'error': 'Invalid template: ' + '; '.join(errors)}), 400
    
    update_doc = {'updated_at': datetime.utcnow().isoformat()}
    for field in allowed_fields:
        if field in data:
            # Map url_template to url
            if field == 'url_template':
                update_doc['url'] = data[field]
            # Map response_template to template
            elif field == 'response_template':
                update_doc['template'] = data[field]
            # Map is_enabled to enabled
            elif field == 'is_enabled':
                update_doc['enabled'] = data[field]
            else:
                update_doc[field] = data[field]
    
    es.update('api_configs', config_id, {'doc': update_doc})
    
    # Get updated config
    updated = es.get('api_configs', config_id)['_source']
    updated['id'] = config_id
    if updated.get('auth_token'):
        updated['auth_token'] = '***'
    
    return jsonify({
        'message': 'API configuration updated',
        'config': updated
    })


@api_config_bp.route('/<config_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_api_config(config_id):
    """Delete an API configuration."""
    es = ElasticsearchService()
    
    result = es.get('api_configs', config_id)
    
    if not result:
        return jsonify({'error': 'API configuration not found'}), 404
    
    config = result['_source']
    
    if config['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    es.delete('api_configs', config_id)
    
    return jsonify({'message': 'API configuration deleted'})


@api_config_bp.route('/test', methods=['POST'])
@login_or_api_key_required
def test_api_config_template():
    """
    Test an API configuration template without saving it.
    
    Expected JSON body:
    {
        "url_template": "https://api.example.com/{value}",
        "method": "GET",
        "headers": {},
        "response_template": {},
        "test_value": "8.8.8.8"
    }
    """
    data = request.get_json()
    
    if not data or not data.get('url_template') or not data.get('test_value'):
        return jsonify({'error': 'url_template and test_value are required'}), 400
    
    enrichment = EnrichmentService()
    
    try:
        api_result = enrichment.call_external_api(data, data['test_value'])
        
        return jsonify({
            'success': True,
            'raw_response': api_result.get('raw_response'),
            'transformed': api_result.get('transformed'),
            'stix_indicator': api_result.get('stix_indicator')
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@api_config_bp.route('/<config_id>/test', methods=['POST'])
@login_or_api_key_required
def test_api_config(config_id):
    """
    Test an API configuration with a sample value.
    
    Expected JSON body:
    {
        "value": "8.8.8.8",
        "type": "ipv4"
    }
    """
    data = request.get_json()
    
    if not data or not data.get('value'):
        return jsonify({'error': 'value is required'}), 400
    
    es = ElasticsearchService()
    
    result = es.get('api_configs', config_id)
    
    if not result:
        return jsonify({'error': 'API configuration not found'}), 404
    
    config = result['_source']
    
    if config['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Test the API
    enrichment = EnrichmentService()
    
    try:
        api_result = enrichment.call_external_api(config, data['value'])
        
        return jsonify({
            'success': True,
            'raw_response': api_result.get('raw_response'),
            'transformed': api_result.get('transformed'),
            'stix_indicator': api_result.get('stix_indicator')
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@api_config_bp.route('/enrich', methods=['POST'])
@login_or_api_key_required
def enrich_ioc():
    """
    Enrich an IOC value using external APIs.
    
    Expected JSON body:
    {
        "value": "8.8.8.8",
        "type": "ipv4" (optional),
        "api_ids": ["api_id_1", "api_id_2"] (optional - specific APIs to use)
    }
    """
    import logging
    logger = logging.getLogger(__name__)
    
    data = request.get_json()
    
    if not data or not data.get('value'):
        return jsonify({'error': 'value is required'}), 400
    
    logger.info(f'[API] Enrichment request for value: {data["value"]}, type: {data.get("type", "auto")}, user: {g.current_user.id}')
    
    enrichment = EnrichmentService()
    
    try:
        # If specific APIs requested, use them; otherwise use all enabled
        api_ids = data.get('api_ids', [])
        
        if api_ids:
            logger.info(f'[API] Enriching with specific APIs: {api_ids}')
            # Enrich with specific APIs
            results = enrichment.enrich_value_with_apis(
                value=data['value'],
                ioc_type=data.get('type'),
                user_id=g.current_user.id,
                api_ids=api_ids
            )
        else:
            logger.info(f'[API] Enriching with all enabled APIs')
            # Enrich with all enabled APIs
            results = enrichment.enrich_value(
                value=data['value'],
                ioc_type=data.get('type'),
                user_id=g.current_user.id
            )
        
        logger.info(f'[API] Enrichment completed with {len(results)} results')
        
        return jsonify({
            'value': data['value'],
            'type': data.get('type'),
            'results': results
        })
    
    except Exception as e:
        import traceback
        logger.error(f'[API] Enrichment error: {str(e)}', exc_info=True)
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400
