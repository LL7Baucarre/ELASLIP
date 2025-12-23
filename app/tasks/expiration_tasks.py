"""Expiration tasks for IOC lifecycle management."""

from datetime import datetime
from celery import shared_task

from app.services.ioc_service import IOCService
from app.services.audit_service import AuditService


@shared_task(name='tasks.check_expired_iocs')
def check_expired_iocs():
    """
    Check for expired IOCs and archive them.
    This task should be scheduled to run daily.
    """
    service = IOCService()
    audit = AuditService()
    
    result = service.archive_expired_iocs()
    
    # Log the action
    audit.log(
        action='batch_archive',
        entity_type='ioc',
        entity_id='system',
        username='system',
        entity_name='Expired IOCs Archive',
        changes={
            'archived': result['archived'],
            'total_expired': result['total_expired']
        }
    )
    
    return result


@shared_task(name='tasks.check_expiring_soon')
def check_expiring_soon(days: int = 7):
    """
    Check for IOCs expiring soon and trigger notifications.
    This task should be scheduled to run daily.
    """
    service = IOCService()
    
    expiring = service.get_expiring_soon(days=days)
    
    # Trigger webhooks for each expiring IOC
    for ioc in expiring:
        service._trigger_webhook('ioc.expiring_soon', {
            'ioc': ioc,
            'days_until_expiration': days,
            'valid_until': ioc.get('valid_until')
        })
    
    return {
        'expiring_count': len(expiring),
        'days': days
    }


@shared_task(name='tasks.cleanup_old_versions')
def cleanup_old_versions(keep_versions: int = 50):
    """
    Clean up old IOC versions to save storage.
    Keeps the most recent N versions for each IOC.
    """
    from app.services.elasticsearch_service import ElasticsearchService
    
    es = ElasticsearchService()
    deleted = 0
    
    # Get all IOC IDs with versions
    result = es.search('ioc_versions', {
        'size': 0,
        'aggs': {
            'by_ioc': {
                'terms': {'field': 'ioc_id', 'size': 10000}
            }
        }
    })
    
    for bucket in result.get('aggregations', {}).get('by_ioc', {}).get('buckets', []):
        ioc_id = bucket['key']
        version_count = bucket['doc_count']
        
        if version_count > keep_versions:
            # Get versions to delete (oldest ones)
            to_delete = es.search('ioc_versions', {
                'query': {'term': {'ioc_id': ioc_id}},
                'sort': [{'version_number': {'order': 'asc'}}],
                'size': version_count - keep_versions,
                '_source': ['id']
            })
            
            for hit in to_delete['hits']['hits']:
                try:
                    es.delete('ioc_versions', hit['_id'])
                    deleted += 1
                except Exception:
                    pass
    
    return {'deleted_versions': deleted}


@shared_task(name='tasks.update_risk_scores')
def update_risk_scores():
    """
    Recalculate risk scores for all IOCs.
    Useful after changing the scoring formula.
    """
    from app.services.elasticsearch_service import ElasticsearchService
    
    service = IOCService()
    es = ElasticsearchService()
    updated = 0
    
    # Get all IOCs
    result = es.search('ioc', {
        'query': {'match_all': {}},
        'size': 10000,
        '_source': ['threat_level', 'confidence', 'tlp', 'risk_score']
    })
    
    for hit in result['hits']['hits']:
        ioc_id = hit['_id']
        doc = hit['_source']
        
        new_score = service.calculate_risk_score(
            doc.get('threat_level'),
            doc.get('confidence'),
            doc.get('tlp')
        )
        
        current_score = doc.get('risk_score', 0)
        
        if new_score != current_score:
            try:
                es.update('ioc', ioc_id, {'doc': {'risk_score': new_score}})
                updated += 1
            except Exception:
                pass
    
    return {'updated': updated}


@shared_task(name='tasks.cleanup_old_audit_logs')
def cleanup_old_audit_logs(days: int = 90):
    """
    Clean up audit logs older than specified days.
    """
    from datetime import timedelta
    from app.services.elasticsearch_service import ElasticsearchService
    
    es = ElasticsearchService()
    
    cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
    
    # Delete old logs
    result = es.es.delete_by_query(
        index=es._get_index_name('audit_logs'),
        body={
            'query': {
                'range': {
                    'timestamp': {'lt': cutoff_date}
                }
            }
        }
    )
    
    return {'deleted': result.get('deleted', 0)}
