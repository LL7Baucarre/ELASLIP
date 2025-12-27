"""Webhook Tasks for Celery."""

import json
import secrets
from datetime import datetime
from typing import Dict, Any

import requests

from app import celery
from app.services.elasticsearch_service import ElasticsearchService


@celery.task(bind=True, max_retries=3, default_retry_delay=5)
def dispatch_webhook(self, event: str, data: Dict[str, Any]):
    """
    Dispatch webhooks for an event.
    
    Args:
        event: Event type (e.g., 'ioc.created')
        data: Event data (IOC or import result)
    """
    es = ElasticsearchService()
    
    # Find all webhooks subscribed to this event
    result = es.search('webhooks', {
        'query': {
            'bool': {
                'must': [
                    {'term': {'enabled': True}},
                    {'term': {'events': event}}
                ]
            }
        },
        'size': 100
    })
    
    for hit in result['hits']['hits']:
        webhook = hit['_source']
        webhook['id'] = hit['_id']
        
        # Send webhook asynchronously
        send_webhook.delay(webhook['id'], webhook['url'], event, data)


@celery.task(bind=True, max_retries=3, default_retry_delay=5)
def send_webhook(self, webhook_id: str, url: str, event: str, data: Dict[str, Any]):
    """
    Send a webhook request.
    
    Args:
        webhook_id: Webhook ID for logging
        url: Destination URL
        event: Event type
        data: Event data
    """
    es = ElasticsearchService()
    
    # Build payload
    payload = {
        'event': event,
        'timestamp': datetime.utcnow().isoformat(),
        'data': data
    }
    
    log_entry = {
        'id': secrets.token_hex(16),
        'webhook_id': webhook_id,
        'event_type': event,
        'payload': payload,
        'timestamp': datetime.utcnow().isoformat(),
        'retry_count': self.request.retries
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        log_entry['status_code'] = response.status_code
        log_entry['response_body'] = response.text[:1000]  # Limit response size
        log_entry['success'] = response.status_code < 400
        
        if response.status_code >= 400:
            log_entry['error_message'] = f'HTTP {response.status_code}'
            
            # Retry on server errors
            if response.status_code >= 500 and self.request.retries < self.max_retries:
                save_webhook_log(es, log_entry)
                raise self.retry(exc=Exception(f'Server error: {response.status_code}'))
        
    except requests.exceptions.RequestException as e:
        log_entry['success'] = False
        log_entry['error_message'] = str(e)
        log_entry['status_code'] = None
        
        # Retry on connection errors
        if self.request.retries < self.max_retries:
            save_webhook_log(es, log_entry)
            raise self.retry(exc=e)
    
    # Save log
    save_webhook_log(es, log_entry)
    
    return log_entry['success']


def save_webhook_log(es: ElasticsearchService, log_entry: Dict):
    """Save webhook log to Elasticsearch."""
    try:
        es.index('webhook_logs', log_entry['id'], log_entry)
    except Exception:
        pass  # Don't fail on logging errors


def test_webhook(webhook: Dict) -> Dict:
    """
    Test a webhook by sending a sample payload.
    
    Args:
        webhook: Webhook configuration
    
    Returns:
        Test result with success status and response
    """
    url = webhook['url']
    
    # Build test payload
    payload = {
        'event': 'webhook.test',
        'timestamp': datetime.utcnow().isoformat(),
        'data': {
            'message': 'This is a test webhook from IOC Manager',
            'webhook_id': webhook.get('id'),
            'webhook_name': webhook.get('name')
        }
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        return {
            'success': response.status_code < 400,
            'status_code': response.status_code,
            'response': response.text[:500]
        }
        
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'error': str(e)
        }
