"""External API Configuration Routes."""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.services.enrichment_service import EnrichmentService

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
        config['id'] = hit['_id']
        # Don't expose auth token
        if 'auth_token' in config:
            config['auth_token'] = '***' if config['auth_token'] else None
        configs.append(config)
    
    return jsonify({'configs': configs})


@api_config_bp.route('', methods=['POST'])
@login_or_api_key_required
def create_api_config():
    """
    Create a new external API configuration.
    
    Expected JSON body:
    {
        "name": "VirusTotal",
        "description": "VirusTotal API",
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
    
    required_fields = ['name', 'url']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    es = ElasticsearchService()
    config_id = secrets.token_hex(16)
    
    config = {
        'id': config_id,
        'user_id': g.current_user.id,
        'name': data['name'],
        'description': data.get('description', ''),
        'url': data['url'],
        'method': data.get('method', 'GET').upper(),
        'headers': data.get('headers', {}),
        'auth_type': data.get('auth_type', 'none'),
        'auth_token': data.get('auth_token'),
        'template': data.get('template', {}),
        'enabled': data.get('enabled', True),
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
    
    return jsonify(config)


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
    allowed_fields = ['name', 'description', 'url', 'method', 'headers', 
                      'auth_type', 'auth_token', 'template', 'enabled']
    
    update_doc = {'updated_at': datetime.utcnow().isoformat()}
    for field in allowed_fields:
        if field in data:
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
            'transformed': api_result.get('transformed')
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
    Enrich an IOC value using all enabled external APIs.
    
    Expected JSON body:
    {
        "value": "8.8.8.8",
        "type": "ipv4" (optional)
    }
    """
    data = request.get_json()
    
    if not data or not data.get('value'):
        return jsonify({'error': 'value is required'}), 400
    
    enrichment = EnrichmentService()
    
    try:
        results = enrichment.enrich_value(
            value=data['value'],
            ioc_type=data.get('type'),
            user_id=g.current_user.id
        )
        
        return jsonify({
            'value': data['value'],
            'type': data.get('type'),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400
