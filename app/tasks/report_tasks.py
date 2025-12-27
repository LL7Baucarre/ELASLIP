"""Tasks for report generation."""

import os
import time
import redis
from celery import shared_task
from datetime import datetime
from app.services.report_service import ReportService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.audit_service import AuditService
from app.services.finops_service import FinOpsService

# Redis lock for ensuring only one report generates at a time
def get_report_lock():
    """Get a Redis connection for report locks."""
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    return redis.from_url(redis_url)

def acquire_report_lock(timeout=600):
    """
    Try to acquire a lock to generate a report.
    Only one report can be generated at a time.
    
    Args:
        timeout: Maximum time in seconds to wait for the lock (default 10 minutes)
    
    Returns:
        True if lock acquired, False if timeout reached
    """
    r = get_report_lock()
    lock_key = 'llm:report_generation_lock'
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Try to set the lock with expiration
        if r.set(lock_key, '1', nx=True, ex=300):  # Lock expires in 5 minutes
            return True
        time.sleep(1)  # Wait 1 second before retry
    
    return False

def release_report_lock():
    """Release the report generation lock."""
    r = get_report_lock()
    lock_key = 'llm:report_generation_lock'
    r.delete(lock_key)


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
    finops = FinOpsService()
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
        
        # Mark as queued while waiting for lock
        report_entry['status'] = 'queued'
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Acquire lock to ensure only one report generates at a time
        if not acquire_report_lock(timeout=600):
            raise RuntimeError("Report generation queue is full. Please try again later.")
        
        # Update status to processing once we have the lock
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        try:
            # Generate report
            report_data = report_service.generate_ioc_report(ioc_id)
            
            # Record token usage if available
            token_usage = report_data.get('token_usage', {})
            if token_usage:
                finops.record_token_usage(
                    report_type='ioc',
                    entity_id=ioc_id,
                    entity_name=report_data.get('ioc_value', ioc_id),
                    prompt_tokens=token_usage.get('prompt_tokens', 0),
                    completion_tokens=token_usage.get('completion_tokens', 0),
                    user_id=user_id
                )
        finally:
            # Always release the lock
            release_report_lock()
        
        # Save completed report with entity name
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        report_entry['entity_name'] = report_data.get('ioc_value', ioc_id)
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
    finops = FinOpsService()
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
        
        # Mark as queued while waiting for lock
        report_entry['status'] = 'queued'
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Acquire lock to ensure only one report generates at a time
        if not acquire_report_lock(timeout=600):
            raise RuntimeError("Report generation queue is full. Please try again later.")
        
        # Update status to processing once we have the lock
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        try:
            # Generate report
            report_data = report_service.generate_case_report(case_id)
            
            # Record token usage if available
            token_usage = report_data.get('token_usage', {})
            if token_usage:
                finops.record_token_usage(
                    report_type='case',
                    entity_id=case_id,
                    entity_name=report_data.get('case_name', case_id),
                    prompt_tokens=token_usage.get('prompt_tokens', 0),
                    completion_tokens=token_usage.get('completion_tokens', 0),
                    user_id=user_id
                )
        finally:
            # Always release the lock
            release_report_lock()
        
        # Save completed report with entity name
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        report_entry['entity_name'] = report_data.get('case_name', case_id)
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
    finops = FinOpsService()
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
        
        # Mark as queued while waiting for lock
        report_entry['status'] = 'queued'
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Acquire lock to ensure only one report generates at a time
        if not acquire_report_lock(timeout=600):
            raise RuntimeError("Report generation queue is full. Please try again later.")
        
        # Update status to processing once we have the lock
        report_entry['status'] = 'processing'
        report_entry['started_at'] = datetime.utcnow().isoformat()
        es.index('app_config', f'report_{task_id}', report_entry)
        
        try:
            # Generate report
            report_data = report_service.generate_incident_report(incident_id)
            
            # Record token usage if available
            token_usage = report_data.get('token_usage', {})
            if token_usage:
                finops.record_token_usage(
                    report_type='incident',
                    entity_id=incident_id,
                    entity_name=report_data.get('incident_name', incident_id),
                    prompt_tokens=token_usage.get('prompt_tokens', 0),
                    completion_tokens=token_usage.get('completion_tokens', 0),
                    user_id=user_id
                )
        finally:
            # Always release the lock
            release_report_lock()
        
        # Save completed report with entity name
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        report_entry['entity_name'] = report_data.get('incident_name', incident_id)
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


@shared_task(name='tasks.generate_checklist_report')
def generate_checklist_report(checklist_id: str, user_id: str = 'system'):
    """
    Generate a report for a checklist asynchronously.
    
    Args:
        checklist_id: The checklist document ID
        user_id: User ID who initiated the report
    """
    import sys
    
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return {'status': 'error', 'error': 'LLM not enabled'}
    
    es = ElasticsearchService()
    report_service = ReportService()
    audit = AuditService()
    finops = FinOpsService()
    
    # Get task ID from Celery
    task_id = generate_checklist_report.request.id
    
    print(f"DEBUG: Starting checklist report generation. Task ID: {task_id}, Checklist ID: {checklist_id}", file=sys.stderr)
    
    # Initialize report_entry early for error handling
    report_entry = {
        'id': task_id,
        'type': 'checklist',
        'entity_id': checklist_id,
        'status': 'pending',
        'created_at': datetime.utcnow().isoformat(),
        'started_at': None,
        'completed_at': None,
        'user_id': user_id,
        'error': None,
        'report_data': None
    }
    
    try:
        # Get checklist data
        from app.services.checklist_service import ChecklistService
        checklist_service = ChecklistService()
        checklist = checklist_service.get_checklist(checklist_id)
        
        print(f"DEBUG: Retrieved checklist: {checklist is not None}", file=sys.stderr)
        
        if not checklist:
            report_entry['status'] = 'failed'
            report_entry['error'] = 'Checklist not found'
            report_entry['completed_at'] = datetime.utcnow().isoformat()
            es.index('app_config', f'report_{task_id}', report_entry)
            return {'status': 'error', 'error': 'Checklist not found', 'task_id': task_id}
        
        # Save pending report
        print(f"DEBUG: Saving pending report to {f'report_{task_id}'}", file=sys.stderr)
        es.index('app_config', f'report_{task_id}', report_entry)
        
        # Generate report
        report_data = {
            'checklist_id': checklist_id,
            'checklist_title': checklist.get('title', 'Untitled Checklist'),
            'description': checklist.get('description', ''),
            'status': checklist.get('status', 'unknown'),
            'items': checklist.get('items', []),
            'created_by': checklist.get('created_by', 'unknown'),
            'created_at': checklist.get('created_at'),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        print(f"DEBUG: Generated report data with {len(report_data.get('items', []))} items", file=sys.stderr)
        
        # Call LLM to enhance the report if configured
        if report_service.is_configured():
            print(f"DEBUG: LLM is configured, waiting for queue slot", file=sys.stderr)
            
            # Mark as queued while waiting for lock
            report_entry['status'] = 'queued'
            es.index('app_config', f'report_{task_id}', report_entry)
            
            try:
                # Acquire lock to ensure only one report generates at a time
                if not acquire_report_lock(timeout=600):
                    print(f"DEBUG: Failed to acquire report lock after timeout", file=sys.stderr)
                    raise RuntimeError("Report generation queue is full. Please try again later.")
                
                # Update status to processing once we have the lock
                report_entry['status'] = 'processing'
                report_entry['started_at'] = datetime.utcnow().isoformat()
                es.index('app_config', f'report_{task_id}', report_entry)
                
                try:
                    print(f"DEBUG: Lock acquired, generating enhanced report", file=sys.stderr)
                    enhanced = report_service.generate_checklist_report(checklist_id)
                    print(f"DEBUG: LLM generated enhanced analysis", file=sys.stderr)
                    report_data['analysis'] = enhanced.get('analysis', '')
                    
                    # Record token usage if available
                    token_usage = enhanced.get('token_usage', {})
                    if token_usage:
                        finops.record_token_usage(
                            report_type='checklist',
                            entity_id=checklist_id,
                            entity_name=enhanced.get('checklist_title', checklist_id),
                            prompt_tokens=token_usage.get('prompt_tokens', 0),
                            completion_tokens=token_usage.get('completion_tokens', 0),
                            user_id=user_id
                        )
                finally:
                    # Always release the lock
                    release_report_lock()
                    print(f"DEBUG: Report lock released", file=sys.stderr)
            except Exception as llm_err:
                print(f"DEBUG: LLM enhancement failed: {str(llm_err)}", file=sys.stderr)
                # Continue without LLM enhancement
        else:
            print(f"DEBUG: LLM not configured, skipping enhancement", file=sys.stderr)
        
        # Save completed report
        report_entry['status'] = 'completed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['report_data'] = report_data
        report_entry['entity_name'] = checklist.get('title', checklist_id)
        
        print(f"DEBUG: Saving completed report", file=sys.stderr)
        es.index('app_config', f'report_{task_id}', report_entry)
        
        print(f"DEBUG: Report saved successfully. Stored at app_config/report_{task_id}", file=sys.stderr)
        
        audit.log(
            action='report_generated',
            entity_type='checklist',
            entity_id=checklist_id,
            username=user_id,
            entity_name=f'Checklist Report {checklist_id}',
            changes={'task_id': task_id}
        )
        
        return {'status': 'completed', 'task_id': task_id, 'report': report_data}
    except Exception as e:
        import traceback
        print(f"DEBUG: Exception in generate_checklist_report: {str(e)}", file=sys.stderr)
        print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
        
        report_entry['status'] = 'failed'
        report_entry['completed_at'] = datetime.utcnow().isoformat()
        report_entry['error'] = str(e)
        
        try:
            es.index('app_config', f'report_{task_id}', report_entry)
        except Exception as save_err:
            print(f"DEBUG: Failed to save error report: {str(save_err)}", file=sys.stderr)
        
        audit.log(
            action='report_generation_failed',
            entity_type='checklist',
            entity_id=checklist_id,
            username=user_id,
            entity_name=f'Checklist Report {checklist_id}',
            changes={'error': str(e)}
        )
        
        return {'status': 'error', 'error': str(e), 'task_id': task_id}
