"""Webhook API Routes."""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.tasks.webhook_tasks import test_webhook

webhook_bp = Blueprint('webhooks', __name__)

# Supported webhook events
WEBHOOK_EVENTS = [
    'ioc.created',
    'ioc.updated',
    'ioc.deleted',
    'import.completed'
]


@webhook_bp.route('', methods=['GET'])
@login_or_api_key_required
def list_webhooks():
    """List all webhooks for current user."""
    es = ElasticsearchService()
    
    result = es.search('webhooks', {
        'query': {'term': {'user_id': g.current_user.id}},
        'size': 100
    })
    
    webhooks = []
    for hit in result['hits']['hits']:
        webhook = hit['_source']
        webhook['id'] = hit['_id']
        webhooks.append(webhook)
    
    return jsonify({
        'webhooks': webhooks,
        'available_events': WEBHOOK_EVENTS
    })


@webhook_bp.route('', methods=['POST'])
@login_or_api_key_required
def create_webhook():
    """
    Create a new webhook.
    
    Expected JSON body:
    {
        "name": "My Webhook",
        "url": "https://example.com/webhook",
        "events": ["ioc.created", "ioc.updated"],
        "enabled": true
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    required_fields = ['name', 'url', 'events']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    # Validate URL
    url = data['url']
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    
    # Validate events
    events = data['events']
    if not isinstance(events, list):
        return jsonify({'error': 'events must be a list'}), 400
    
    invalid_events = [e for e in events if e not in WEBHOOK_EVENTS]
    if invalid_events:
        return jsonify({
            'error': f'Invalid events: {invalid_events}',
            'available_events': WEBHOOK_EVENTS
        }), 400
    
    es = ElasticsearchService()
    webhook_id = secrets.token_hex(16)
    
    webhook = {
        'id': webhook_id,
        'user_id': g.current_user.id,
        'name': data['name'],
        'url': url,
        'events': events,
        'enabled': data.get('enabled', True),
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    
    es.index('webhooks', webhook_id, webhook)
    
    return jsonify({
        'message': 'Webhook created',
        'webhook': webhook
    }), 201


@webhook_bp.route('/<webhook_id>', methods=['GET'])
@login_or_api_key_required
def get_webhook(webhook_id):
    """Get a single webhook."""
    es = ElasticsearchService()
    
    result = es.get('webhooks', webhook_id)
    
    if not result:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook = result['_source']
    
    if webhook['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    webhook['id'] = webhook_id
    
    return jsonify(webhook)


@webhook_bp.route('/<webhook_id>', methods=['PUT'])
@login_or_api_key_required
def update_webhook(webhook_id):
    """Update a webhook."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    es = ElasticsearchService()
    
    result = es.get('webhooks', webhook_id)
    
    if not result:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook = result['_source']
    
    if webhook['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Validate events if provided
    if 'events' in data:
        events = data['events']
        if not isinstance(events, list):
            return jsonify({'error': 'events must be a list'}), 400
        
        invalid_events = [e for e in events if e not in WEBHOOK_EVENTS]
        if invalid_events:
            return jsonify({
                'error': f'Invalid events: {invalid_events}',
                'available_events': WEBHOOK_EVENTS
            }), 400
    
    # Update allowed fields
    allowed_fields = ['name', 'url', 'events', 'enabled']
    update_doc = {'updated_at': datetime.utcnow().isoformat()}
    
    for field in allowed_fields:
        if field in data:
            update_doc[field] = data[field]
    
    es.update('webhooks', webhook_id, {'doc': update_doc})
    
    # Get updated webhook
    updated = es.get('webhooks', webhook_id)['_source']
    updated['id'] = webhook_id
    
    return jsonify({
        'message': 'Webhook updated',
        'webhook': updated
    })


@webhook_bp.route('/<webhook_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_webhook(webhook_id):
    """Delete a webhook."""
    es = ElasticsearchService()
    
    result = es.get('webhooks', webhook_id)
    
    if not result:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook = result['_source']
    
    if webhook['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    es.delete('webhooks', webhook_id)
    
    return jsonify({'message': 'Webhook deleted'})


@webhook_bp.route('/test', methods=['POST'])
@login_or_api_key_required
def test_webhook_url():
    """Test a webhook URL without saving it."""
    data = request.get_json()
    url = data.get('url')
    secret = data.get('secret')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        test_result = test_webhook({
            'url': url,
            'secret': secret
        })
        return jsonify({
            'success': test_result['success'],
            'status_code': test_result.get('status_code'),
            'response': test_result.get('response'),
            'error': test_result.get('error')
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@webhook_bp.route('/<webhook_id>/test', methods=['POST'])
@login_or_api_key_required
def test_webhook_endpoint(webhook_id):
    """
    Test a webhook by sending a sample payload.
    """
    es = ElasticsearchService()
    
    result = es.get('webhooks', webhook_id)
    
    if not result:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook = result['_source']
    
    if webhook['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Send test webhook
    try:
        test_result = test_webhook(webhook)
        return jsonify({
            'success': test_result['success'],
            'status_code': test_result.get('status_code'),
            'response': test_result.get('response'),
            'error': test_result.get('error')
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@webhook_bp.route('/<webhook_id>/logs', methods=['GET'])
@login_or_api_key_required
def get_webhook_logs(webhook_id):
    """Get logs for a webhook."""
    es = ElasticsearchService()
    
    # Verify ownership
    result = es.get('webhooks', webhook_id)
    
    if not result:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook = result['_source']
    
    if webhook['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Get logs
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    from_idx = (page - 1) * per_page
    
    logs_result = es.search('webhook_logs', {
        'query': {'term': {'webhook_id': webhook_id}},
        'from': from_idx,
        'size': per_page,
        'sort': [{'timestamp': {'order': 'desc'}}]
    })
    
    logs = []
    for hit in logs_result['hits']['hits']:
        log = hit['_source']
        log['id'] = hit['_id']
        logs.append(log)
    
    return jsonify({
        'logs': logs,
        'total': logs_result['hits']['total']['value'],
        'page': page,
        'per_page': per_page
    })


@webhook_bp.route('/logs', methods=['GET'])
@login_or_api_key_required
def get_all_webhook_logs():
    """Get logs for all user webhooks."""
    es = ElasticsearchService()
    
    # Get all user webhooks
    webhooks_result = es.search('webhooks', {
        'query': {'term': {'user_id': g.current_user.id}},
        'size': 1000
    })
    
    webhook_ids = [hit['_id'] for hit in webhooks_result['hits']['hits']]
    
    if not webhook_ids:
        return jsonify({'logs': []})
    
    # Get logs for all webhooks
    page = request.args.get('page', 1, type=int)
    size = min(request.args.get('size', 20, type=int), 100)
    
    from_idx = (page - 1) * size
    
    logs_result = es.search('webhook_logs', {
        'query': {'terms': {'webhook_id': webhook_ids}},
        'from': from_idx,
        'size': size,
        'sort': [{'timestamp': {'order': 'desc'}}]
    })
    
    logs = []
    for hit in logs_result['hits']['hits']:
        log = hit['_source']
        log['id'] = hit['_id']
        logs.append(log)
    
    return jsonify({
        'logs': logs,
        'total': logs_result['hits']['total']['value'],
        'page': page,
        'size': size
    })


@webhook_bp.route('/logs/<log_id>', methods=['GET'])
@login_or_api_key_required
def get_webhook_log(log_id):
    """Get a single webhook log entry."""
    es = ElasticsearchService()
    
    # Get the log entry
    log_result = es.get('webhook_logs', log_id)
    
    if not log_result:
        return jsonify({'error': 'Log entry not found'}), 404
    
    log = log_result['_source']
    
    # Verify ownership through webhook
    webhook_result = es.get('webhooks', log['webhook_id'])
    
    if webhook_result and webhook_result['_source']['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    log['id'] = log_id
    return jsonify({'log': log})


@webhook_bp.route('/logs/<log_id>/retry', methods=['POST'])
@login_or_api_key_required
def retry_webhook_delivery(log_id):
    """Retry a failed webhook delivery."""
    es = ElasticsearchService()
    
    # Get the log entry
    log_result = es.get('webhook_logs', log_id)
    
    if not log_result:
        return jsonify({'error': 'Log entry not found'}), 404
    
    log = log_result['_source']
    
    # Verify ownership through webhook
    webhook_result = es.get('webhooks', log['webhook_id'])
    
    if webhook_result and webhook_result['_source']['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Queue retry task
    from app.tasks.webhook_tasks import dispatch_webhook
    dispatch_webhook.delay(
        webhook_id=log['webhook_id'],
        event=log['event'],
        payload=log['payload']
    )
    
    return jsonify({'success': True, 'message': 'Retry queued'})


@webhook_bp.route('/events', methods=['GET'])
def get_available_events():
    """Get list of available webhook events."""
    return jsonify({'events': WEBHOOK_EVENTS})
