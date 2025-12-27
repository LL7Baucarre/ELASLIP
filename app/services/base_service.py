"""Base service class with common list operations."""

from typing import Dict, List, Optional, Any
from app.services.elasticsearch_service import ElasticsearchService


class BaseListService:
    """Base service for common list operations with pagination and sorting."""
    
    SEVERITY_ORDER = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'informational': 0
    }
    
    PRIORITY_ORDER = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    def __init__(self, es: Optional[ElasticsearchService] = None):
        """Initialize service with Elasticsearch client."""
        self.es = es or ElasticsearchService()
    
    def build_hits_from_search(self, result: Dict[str, Any]) -> List[Dict]:
        """
        Transform Elasticsearch search result hits to list of documents with IDs.
        
        Args:
            result: Elasticsearch search result
            
        Returns:
            List of documents with '_id' added as 'id'
        """
        items = []
        for hit in result.get('hits', {}).get('hits', []):
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        return items
    
    def build_paginated_response(self, result: Dict[str, Any], page: int, 
                                per_page: int, items: Optional[List] = None) -> Dict:
        """
        Build standardized paginated response.
        
        Args:
            result: Elasticsearch search result
            page: Current page number
            per_page: Items per page
            items: Optional pre-built items list (uses search result if None)
            
        Returns:
            Standardized response dict
        """
        if items is None:
            items = self.build_hits_from_search(result)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def build_sort_config(self, sort_field: str, sort_order: str, 
                         is_severity: bool = False) -> Dict:
        """
        Build Elasticsearch sort configuration.
        
        Args:
            sort_field: Field to sort by
            sort_order: Sort order ('asc' or 'desc')
            is_severity: Use severity mapping script
            
        Returns:
            Elasticsearch sort config
        """
        if is_severity and sort_field in ('severity', 'priority'):
            severity_map = self.SEVERITY_ORDER if sort_field == 'severity' else self.PRIORITY_ORDER
            return {
                '_script': {
                    'type': 'number',
                    'script': {
                        'source': f"params['{sort_field}_order'].getOrDefault(doc['{sort_field}'].value, 0)",
                        'params': {f'{sort_field}_order': severity_map}
                    },
                    'order': sort_order
                }
            }
        else:
            return {sort_field: {'order': sort_order}}
    
    def parse_sort_param(self, sort_param: Optional[str], default_field: str = 'created_at') -> tuple:
        """
        Parse sort parameter into field and order.
        
        Args:
            sort_param: Sort parameter string (e.g., 'severity_desc', 'title_asc')
            default_field: Default sort field if not specified
            
        Returns:
            Tuple of (sort_field, sort_order)
        """
        sort_field = default_field
        sort_order = 'desc'
        
        if sort_param:
            if '_asc' in sort_param:
                sort_order = 'asc'
                sort_field = sort_param.replace('_asc', '')
            elif '_desc' in sort_param:
                sort_order = 'desc'
                sort_field = sort_param.replace('_desc', '')
        
        return sort_field, sort_order
