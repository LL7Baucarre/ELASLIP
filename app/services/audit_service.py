"""Audit Service for tracking user actions."""

import secrets
from datetime import datetime
from typing import Dict, List, Optional

from app.services.elasticsearch_service import ElasticsearchService


class AuditService:
    """Service for logging and querying audit events."""
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.index = 'ioc_manager_audit_logs'
    
    def log(self, 
            action: str,
            entity_type: str,
            entity_id: str,
            user_id: str = None,
            username: str = None,
            entity_name: str = None,
            changes: Dict = None,
            old_values: Dict = None,
            new_values: Dict = None,
            ip_address: str = None,
            user_agent: str = None) -> Dict:
        """
        Log an audit event.
        
        Args:
            action: Action type (create, update, delete, login, export, etc.)
            entity_type: Type of entity (ioc, user, webhook, api_key, etc.)
            entity_id: ID of the entity
            user_id: User performing the action
            username: Username for display
            entity_name: Human-readable entity name
            changes: Summary of changes made
            old_values: Previous values before change
            new_values: New values after change
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            The created audit log entry
        """
        log_id = secrets.token_hex(16)
        
        log_entry = {
            'id': log_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'user_id': user_id,
            'username': username or 'system',
            'entity_name': entity_name,
            'changes': changes,
            'old_values': old_values,
            'new_values': new_values,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.es.index(self.index, log_id, log_entry)
        
        return log_entry
    
    def list(self, 
             page: int = 1, 
             per_page: int = 50,
             action: str = None,
             entity_type: str = None,
             user_id: str = None,
             entity_id: str = None,
             start_date: str = None,
             end_date: str = None) -> Dict:
        """
        List audit logs with filters.
        
        Args:
            page: Page number
            per_page: Items per page
            action: Filter by action type
            entity_type: Filter by entity type
            user_id: Filter by user
            entity_id: Filter by specific entity
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
        
        Returns:
            Paginated audit logs
        """
        query = {"bool": {"must": []}}
        
        if action:
            query["bool"]["must"].append({"term": {"action": action}})
        
        if entity_type:
            query["bool"]["must"].append({"term": {"entity_type": entity_type}})
        
        if user_id:
            query["bool"]["must"].append({"term": {"user_id": user_id}})
        
        if entity_id:
            query["bool"]["must"].append({"term": {"entity_id": entity_id}})
        
        if start_date or end_date:
            date_range = {}
            if start_date:
                date_range['gte'] = start_date
            if end_date:
                date_range['lte'] = end_date
            query["bool"]["must"].append({"range": {"timestamp": date_range}})
        
        if not query["bool"]["must"]:
            query = {"match_all": {}}
        
        from_idx = (page - 1) * per_page
        
        result = self.es.search(self.index, {
            "query": query,
            "from": from_idx,
            "size": per_page,
            "sort": [{"timestamp": {"order": "desc"}}]
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def get_by_entity(self, entity_type: str, entity_id: str, limit: int = 50) -> List[Dict]:
        """Get audit history for a specific entity."""
        result = self.es.search(self.index, {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'entity_type': entity_type}},
                        {'term': {'entity_id': entity_id}}
                    ]
                }
            },
            'sort': [{'timestamp': {'order': 'desc'}}],
            'size': limit
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return items
    
    def get_user_activity(self, user_id: str, limit: int = 100) -> List[Dict]:
        """Get recent activity for a specific user."""
        result = self.es.search(self.index, {
            'query': {'term': {'user_id': user_id}},
            'sort': [{'timestamp': {'order': 'desc'}}],
            'size': limit
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return items
    
    def get_stats(self, days: int = 7) -> Dict:
        """Get audit statistics for the last N days."""
        from datetime import timedelta
        
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        result = self.es.search(self.index, {
            'query': {
                'range': {'timestamp': {'gte': start_date}}
            },
            'size': 0,
            'aggs': {
                'by_action': {
                    'terms': {'field': 'action', 'size': 20}
                },
                'by_entity_type': {
                    'terms': {'field': 'entity_type', 'size': 20}
                },
                'by_user': {
                    'terms': {'field': 'username', 'size': 20}
                },
                'by_day': {
                    'date_histogram': {
                        'field': 'timestamp',
                        'calendar_interval': 'day'
                    }
                }
            }
        })
        
        aggs = result.get('aggregations', {})
        
        return {
            'total': result['hits']['total']['value'],
            'by_action': {b['key']: b['doc_count'] for b in aggs.get('by_action', {}).get('buckets', [])},
            'by_entity_type': {b['key']: b['doc_count'] for b in aggs.get('by_entity_type', {}).get('buckets', [])},
            'by_user': {b['key']: b['doc_count'] for b in aggs.get('by_user', {}).get('buckets', [])},
            'by_day': [{'date': b['key_as_string'], 'count': b['doc_count']} for b in aggs.get('by_day', {}).get('buckets', [])]
        }
