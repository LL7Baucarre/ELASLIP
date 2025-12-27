"""Service for tracking and analyzing LLM token usage (FinOps)."""

from datetime import datetime, timedelta
from typing import Dict, List, Any
from app.services.elasticsearch_service import ElasticsearchService
import json


class FinOpsService:
    """Service to track and analyze LLM token usage."""
    
    def __init__(self):
        """Initialize FinOps service."""
        self.es = ElasticsearchService()
        self.index_name = 'ioc_manager_finops_token_usage'
    
    def record_token_usage(self, 
                          report_type: str,
                          entity_id: str,
                          entity_name: str,
                          prompt_tokens: int,
                          completion_tokens: int,
                          user_id: str = 'system',
                          model: str = 'mistral') -> str:
        """
        Record token usage for a report generation.
        
        Args:
            report_type: Type of report (ioc, case, incident, checklist)
            entity_id: ID of the entity being reported
            entity_name: Human-readable name of the entity
            prompt_tokens: Number of tokens in the prompt
            completion_tokens: Number of tokens in the completion
            user_id: User who initiated the report
            model: LLM model used
            
        Returns:
            Document ID of the token usage record
        """
        total_tokens = prompt_tokens + completion_tokens
        timestamp = datetime.utcnow()
        
        doc = {
            'timestamp': timestamp.isoformat(),
            'report_type': report_type,
            'entity_id': entity_id,
            'entity_name': entity_name,
            'prompt_tokens': prompt_tokens,
            'completion_tokens': completion_tokens,
            'total_tokens': total_tokens,
            'user_id': user_id,
            'model': model,
            # Additional fields for aggregation
            'date': timestamp.strftime('%Y-%m-%d'),
            'hour': timestamp.strftime('%Y-%m-%d %H:00:00'),
            'month': timestamp.strftime('%Y-%m'),
        }
        
        # Use timestamp as part of doc ID for better indexing
        doc_id = f"{timestamp.timestamp()}_{entity_id}_{report_type}"
        self.es.index(self.index_name, doc_id, doc)
        
        return doc_id
    
    def get_token_usage_timeline(self, 
                                 time_window: str = 'day',
                                 report_types: List[str] = None,
                                 limit_days: int = 30) -> List[Dict[str, Any]]:
        """
        Get token usage aggregated over time.
        
        Args:
            time_window: Aggregation window ('hour', 'day', 'week', 'month')
            report_types: Filter by report types (None = all types)
            limit_days: Number of days to look back
            
        Returns:
            List of aggregated token usage data points
        """
        from_date = (datetime.utcnow() - timedelta(days=limit_days)).isoformat()
        
        # Determine aggregation field based on time_window
        agg_field_map = {
            'hour': 'hour',
            'day': 'date',
            'month': 'month'
        }
        agg_field = agg_field_map.get(time_window, 'date')
        
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": from_date}}}
                ]
            }
        }
        
        # Add report type filter if specified
        if report_types and len(report_types) > 0:
            query["bool"]["must"].append({
                "terms": {"report_type": report_types}
            })
        
        # Build aggregation
        aggs = {
            "by_time": {
                "terms": {
                    "field": agg_field,
                    "size": 500,
                    "order": {"_key": "asc"}
                },
                "aggs": {
                    "total_tokens": {"sum": {"field": "total_tokens"}},
                    "prompt_tokens": {"sum": {"field": "prompt_tokens"}},
                    "completion_tokens": {"sum": {"field": "completion_tokens"}},
                    "count": {"value_count": {"field": "entity_id"}}
                }
            }
        }
        
        try:
            result = self.es.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "aggs": aggs,
                    "size": 0
                }
            )
            
            buckets = result.get('aggregations', {}).get('by_time', {}).get('buckets', [])
            
            timeline = []
            for bucket in buckets:
                timeline.append({
                    'timestamp': bucket['key_as_string'] if 'key_as_string' in bucket else str(bucket['key']),
                    'total_tokens': int(bucket['total_tokens']['value']),
                    'prompt_tokens': int(bucket['prompt_tokens']['value']),
                    'completion_tokens': int(bucket['completion_tokens']['value']),
                    'reports_count': int(bucket['count']['value'])
                })
            
            return timeline
        except Exception as e:
            print(f"Error getting token usage timeline: {str(e)}")
            return []
    
    def get_token_usage_by_report_type(self, limit_days: int = 30) -> Dict[str, Dict[str, Any]]:
        """
        Get token usage breakdown by report type.
        
        Args:
            limit_days: Number of days to look back
            
        Returns:
            Dictionary with breakdown by report type
        """
        from_date = (datetime.utcnow() - timedelta(days=limit_days)).isoformat()
        
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": from_date}}}
                ]
            }
        }
        
        aggs = {
            "by_type": {
                "terms": {
                    "field": "report_type",
                    "size": 20
                },
                "aggs": {
                    "total_tokens": {"sum": {"field": "total_tokens"}},
                    "prompt_tokens": {"sum": {"field": "prompt_tokens"}},
                    "completion_tokens": {"sum": {"field": "completion_tokens"}},
                    "count": {"value_count": {"field": "entity_id"}},
                    "avg_tokens": {"avg": {"field": "total_tokens"}}
                }
            }
        }
        
        try:
            result = self.es.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "aggs": aggs,
                    "size": 0
                }
            )
            
            buckets = result.get('aggregations', {}).get('by_type', {}).get('buckets', [])
            
            breakdown = {}
            for bucket in buckets:
                report_type = bucket['key']
                breakdown[report_type] = {
                    'total_tokens': int(bucket['total_tokens']['value']),
                    'prompt_tokens': int(bucket['prompt_tokens']['value']),
                    'completion_tokens': int(bucket['completion_tokens']['value']),
                    'reports_count': int(bucket['count']['value']),
                    'avg_tokens_per_report': int(bucket['avg_tokens']['value'])
                }
            
            return breakdown
        except Exception as e:
            print(f"Error getting token usage by type: {str(e)}")
            return {}
    
    def get_top_token_consumers(self, limit: int = 10, limit_days: int = 30) -> List[Dict[str, Any]]:
        """
        Get reports that consumed the most tokens.
        
        Args:
            limit: Number of top reports to return
            limit_days: Number of days to look back
            
        Returns:
            List of top consuming reports
        """
        from_date = (datetime.utcnow() - timedelta(days=limit_days)).isoformat()
        
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": from_date}}}
                ]
            }
        }
        
        try:
            result = self.es.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "sort": [{"total_tokens": {"order": "desc"}}],
                    "size": limit
                }
            )
            
            hits = result.get('hits', {}).get('hits', [])
            
            consumers = []
            for hit in hits:
                doc = hit['_source']
                consumers.append({
                    'timestamp': doc['timestamp'],
                    'report_type': doc['report_type'],
                    'entity_name': doc['entity_name'],
                    'total_tokens': doc['total_tokens'],
                    'prompt_tokens': doc['prompt_tokens'],
                    'completion_tokens': doc['completion_tokens'],
                    'user_id': doc.get('user_id', 'unknown'),
                    'model': doc.get('model', 'unknown')
                })
            
            return consumers
        except Exception as e:
            print(f"Error getting top token consumers: {str(e)}")
            return []
    
    def get_statistics(self, limit_days: int = 30) -> Dict[str, Any]:
        """
        Get overall statistics for token usage.
        
        Args:
            limit_days: Number of days to look back
            
        Returns:
            Dictionary with overall statistics
        """
        from_date = (datetime.utcnow() - timedelta(days=limit_days)).isoformat()
        
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": from_date}}}
                ]
            }
        }
        
        aggs = {
            "total_tokens": {"sum": {"field": "total_tokens"}},
            "prompt_tokens": {"sum": {"field": "prompt_tokens"}},
            "completion_tokens": {"sum": {"field": "completion_tokens"}},
            "reports_count": {"value_count": {"field": "entity_id"}},
            "avg_tokens": {"avg": {"field": "total_tokens"}},
            "max_tokens": {"max": {"field": "total_tokens"}},
            "min_tokens": {"min": {"field": "total_tokens"}}
        }
        
        try:
            result = self.es.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "aggs": aggs,
                    "size": 0
                }
            )
            
            agg_results = result.get('aggregations', {})
            
            stats = {
                'total_tokens': int(agg_results.get('total_tokens', {}).get('value') or 0),
                'prompt_tokens': int(agg_results.get('prompt_tokens', {}).get('value') or 0),
                'completion_tokens': int(agg_results.get('completion_tokens', {}).get('value') or 0),
                'reports_count': int(agg_results.get('reports_count', {}).get('value') or 0),
                'avg_tokens_per_report': int(agg_results.get('avg_tokens', {}).get('value') or 0),
                'max_tokens_per_report': int(agg_results.get('max_tokens', {}).get('value') or 0),
                'min_tokens_per_report': int(agg_results.get('min_tokens', {}).get('value') or 0)
            }
            
            return stats
        except Exception as e:
            print(f"Error getting statistics: {str(e)}")
            return {}
