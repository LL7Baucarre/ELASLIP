"""Tasks for report generation."""

import os
from celery import shared_task
from datetime import datetime
from app.services.report_service import ReportService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.audit_service import AuditService


@shared_task(name='tasks.generate_ioc_report')
def generate_ioc_report(ioc_id: str, user_id: str = 'system'):
    """
    Generate a report for an IOC asynchronously.
    
    Args:
        ioc_id: The IOC document ID
        user_id: User ID who initiated the report
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return {'status': 'error', 'error': 'LLM not enabled'}
    
    es = ElasticsearchService()
    report_service = ReportService()
    audit = AuditService()
    task_id = generate_ioc_report.request.id
    
    try:
        # Create report entry
        report_entry = {
            'id': task_id,
            'type': 'ioc',
            'entity_id': ioc_id,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'started_at': None,
            'completed_at': None,
            'user_id': user_id,
            'error': None,
            'report_data': None
        }
        
        # Save pending report
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Update status to processing
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Generate report
        report_data = report_service.generate_ioc_report(ioc_id)
        
        # Save completed report
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generated',
            entity_type='ioc',
            entity_id=ioc_id,
            username=user_id,
            entity_name=f'IOC Report {ioc_id}',
            changes={'task_id': task_id}
        )
        
        return {'status': 'completed', 'task_id': task_id, 'report': report_data}
    except Exception as e:
        report_entry['status'] = 'failed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['error'] = str(e)
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generation_failed',
            entity_type='ioc',
            entity_id=ioc_id,
            username=user_id,
            entity_name=f'IOC Report {ioc_id}',
            changes={'error': str(e)}
        )
        
        return {'status': 'error', 'error': str(e), 'task_id': task_id}


@shared_task(name='tasks.generate_case_report')
def generate_case_report(case_id: str, user_id: str = 'system'):
    """
    Generate a report for a case asynchronously.
    
    Args:
        case_id: The case document ID
        user_id: User ID who initiated the report
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return {'status': 'error', 'error': 'LLM not enabled'}
    
    es = ElasticsearchService()
    report_service = ReportService()
    audit = AuditService()
    task_id = generate_case_report.request.id
    
    try:
        # Create report entry
        report_entry = {
            'id': task_id,
            'type': 'case',
            'entity_id': case_id,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'started_at': None,
            'completed_at': None,
            'user_id': user_id,
            'error': None,
            'report_data': None
        }
        
        # Save pending report
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Update status to processing
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Generate report
        report_data = report_service.generate_case_report(case_id)
        
        # Save completed report
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generated',
            entity_type='case',
            entity_id=case_id,
            username=user_id,
            entity_name=f'Case Report {case_id}',
            changes={'task_id': task_id}
        )
        
        return {'status': 'completed', 'task_id': task_id, 'report': report_data}
    except Exception as e:
        report_entry['status'] = 'failed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['error'] = str(e)
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generation_failed',
            entity_type='case',
            entity_id=case_id,
            username=user_id,
            entity_name=f'Case Report {case_id}',
            changes={'error': str(e)}
        )
        
        return {'status': 'error', 'error': str(e), 'task_id': task_id}


@shared_task(name='tasks.generate_incident_report')
def generate_incident_report(incident_id: str, user_id: str = 'system'):
    """
    Generate a report for an incident asynchronously.
    
    Args:
        incident_id: The incident document ID
        user_id: User ID who initiated the report
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return {'status': 'error', 'error': 'LLM not enabled'}
    
    es = ElasticsearchService()
    report_service = ReportService()
    audit = AuditService()
    task_id = generate_incident_report.request.id
    
    try:
        # Create report entry
        report_entry = {
            'id': task_id,
            'type': 'incident',
            'entity_id': incident_id,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'started_at': None,
            'completed_at': None,
            'user_id': user_id,
            'error': None,
            'report_data': None
        }
        
        # Save pending report
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Update status to processing
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Generate report
        report_data = report_service.generate_incident_report(incident_id)
        
        # Save completed report
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generated',
            entity_type='incident',
            entity_id=incident_id,
            username=user_id,
            entity_name=f'Incident Report {incident_id}',
            changes={'task_id': task_id}
        )
        
        return {'status': 'completed', 'task_id': task_id, 'report': report_data}
    except Exception as e:
        report_entry['status'] = 'failed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['error'] = str(e)
        es.index('app_config', f'report_{task_id}', report_entry)
        
        audit.log(
            action='report_generation_failed',
            entity_type='incident',
            entity_id=incident_id,
            username=user_id,
            entity_name=f'Incident Report {incident_id}',
            changes={'error': str(e)}
        )
        
        return {'status': 'error', 'error': str(e), 'task_id': task_id}


@shared_task(name='tasks.generate_incident_reports')
def generate_incident_reports():
    """
    Generate reports for all open incidents.
    This task should be scheduled to run periodically.
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return {'status': 'skipped', 'reason': 'LLM not enabled'}
    
    es = ElasticsearchService()
    report_service = ReportService()
    audit = AuditService()
    
    try:
        # Get all open incidents
        query = {
            'query': {
                'term': {'status': 'open'}
            },
            'size': 1000
        }
        result = es.search('incidents', query)
        
        incidents = []
        for hit in result.get('hits', {}).get('hits', []):
            doc = hit['_source']
            doc['id'] = hit['_id']
            incidents.append(doc)
        
        generated = 0
        failed = 0
        
        for incident in incidents:
            try:
                # Generate report
                report = report_service.generate_incident_report(incident['id'])
                
                # Store report in incident
                incident['generated_report'] = report
                incident['report_generated_at'] = datetime.utcnow().isoformat()
                
                # Update incident with report
                es.index('incidents', incident['id'], incident)
                
                generated += 1
            except Exception as e:
                failed += 1
                audit.log(
                    action='report_generation_failed',
                    entity_type='incident',
                    entity_id=incident.get('id'),
                    username='system',
                    entity_name=incident.get('name'),
                    changes={'error': str(e)}
                )
        
        # Log task completion
        audit.log(
            action='batch_report_generation',
            entity_type='incident',
            entity_id='system',
            username='system',
            entity_name='Batch Incident Reports',
            changes={
                'generated': generated,
                'failed': failed,
                'total': len(incidents)
            }
        )
        
        return {
            'status': 'completed',
            'generated': generated,
            'failed': failed,
            'total': len(incidents)
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }
