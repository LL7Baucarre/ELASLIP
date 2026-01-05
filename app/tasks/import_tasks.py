"""Import Tasks for Celery - STIX 2.1 Only."""

import json
from datetime import datetime
from typing import Dict, List

from app import celery
from app.services.elasticsearch_service import ElasticsearchService
from app.services.ioc_service import IOCService
from app.models.stix_schema import STIXBundle, STIXIndicator, STIXRelationship


@celery.task(bind=True)
def process_import(self, job_id: str, file_content: str, file_type: str, user_id: str):
    """
    Process an import job asynchronously.
    
    Args:
        job_id: Import job ID
        file_content: Content of the file to import
        file_type: Type of file (stix, misp, openioc, iodef)
        user_id: User ID who initiated the import
    """
    es = ElasticsearchService()
    ioc_service = IOCService()
    
    # Update job status to processing
    update_job_status(es, job_id, 'processing')
    
    result = {
        'added': 0,
        'updated': 0,
        'duplicates': 0,
        'errors': 0,
        'relationships_added': 0,
        'relationships_updated': 0,
        'objects_added': 0,
        'objects_updated': 0,
        'error_details': []
    }
    
    try:
        # Get username for metadata
        username = 'import_user'
        try:
            user_doc = es.get('users', user_id)
            if user_doc:
                username = user_doc.get('_source', {}).get('username', 'import_user')
        except Exception:
            pass
        
        source = {
            'name': f'import_{file_type}',
            'metadata': {
                'job_id': job_id,
                'user_id': user_id,
                'file_type': file_type
            }
        }
        
        # For STIX files, use full parsing to get relationships and objects
        if file_type.lower() == 'stix':
            parsed = parse_stix_full(file_content)
            indicators = parsed['indicators']
            relationships = parsed['relationships']
            stix_objects = parsed['objects']
            
            total_items = len(indicators) + len(relationships) + len(stix_objects)
        else:
            # Parse file based on type
            indicators = parse_file(file_content, file_type)
            relationships = []
            stix_objects = []
            total_items = len(indicators)
        
        update_job_progress(es, job_id, 0, total_items)
        processed = 0
        
        # Process indicators
        for idx, indicator in enumerate(indicators):
            try:
                # Create or update IOC
                ioc, is_new = create_ioc_from_indicator(ioc_service, indicator, source)
                
                if is_new:
                    result['added'] += 1
                else:
                    result['duplicates'] += 1
                
            except Exception as e:
                result['errors'] += 1
                result['error_details'].append({
                    'index': idx,
                    'type': 'indicator',
                    'error': str(e),
                    'indicator': str(indicator)[:200]
                })
            
            processed += 1
            # Update progress every 10 items
            if processed % 10 == 0:
                progress = int(processed / total_items * 100)
                update_job_progress(es, job_id, progress, total_items, processed)
        
        # Process STIX relationships
        if relationships:
            rel_result = import_stix_relationships(es, relationships, user_id, username, job_id)
            result['relationships_added'] = rel_result['added']
            result['relationships_updated'] = rel_result.get('updated', 0)
            result['errors'] += rel_result['errors']
            result['error_details'].extend(rel_result['error_details'])
            processed += len(relationships)
            progress = int(processed / total_items * 100)
            update_job_progress(es, job_id, progress, total_items, processed)
        
        # Process other STIX objects (malware, threat-actor, etc.)
        if stix_objects:
            obj_result = import_stix_objects(es, stix_objects, user_id, username, job_id)
            result['objects_added'] = obj_result['added']
            result['objects_updated'] = obj_result.get('updated', 0)
            result['errors'] += obj_result['errors']
            result['error_details'].extend(obj_result['error_details'])
            processed += len(stix_objects)
        
        # Mark job as completed
        update_job_completed(es, job_id, result)
        
        # Trigger webhook
        trigger_import_webhook(job_id, result)
        
    except Exception as e:
        result['errors'] += 1
        result['error_details'].append({
            'error': f'Failed to process file: {str(e)}'
        })
        update_job_failed(es, job_id, str(e), result)
    
    return result


def parse_file(content: str, file_type: str) -> List:
    """Parse STIX file content."""
    if file_type.lower() != 'stix':
        raise ValueError(f'Unsupported file type: {file_type}. Only STIX 2.1 is supported.')
    return STIXBundle.parse(content)


def parse_stix_full(content: str) -> Dict[str, List]:
    """
    Parse STIX bundle with full support for relationships and other SDOs.
    
    Returns:
        Dictionary with 'indicators', 'relationships', 'objects'
    """
    return STIXBundle.parse_full(content)


def import_stix_relationships(es: ElasticsearchService, relationships: List[Dict], 
                               user_id: str, username: str, job_id: str) -> Dict:
    """
    Import STIX relationships from a bundle with deduplication.
    
    If a relationship with the same ID already exists, adds the new source
    to the existing sources list instead of creating a duplicate.
    
    Returns:
        Dict with 'added', 'updated', 'errors', 'error_details'
    """
    result = {'added': 0, 'updated': 0, 'errors': 0, 'error_details': []}
    
    for rel in relationships:
        try:
            rel_id = rel.get('id', f"relationship--{__import__('uuid').uuid4()}")
            
            # Check if relationship already exists
            existing = None
            try:
                existing = es.get('stix_relationships', rel_id)
            except Exception:
                pass
            
            # Build source info for this import
            source_info = {
                'import_job_id': job_id,
                'user_id': user_id,
                'username': username,
                'imported_at': datetime.utcnow().isoformat()
            }
            
            if existing and existing.get('_source'):
                # Update existing - merge sources
                existing_doc = existing['_source']
                sources = existing_doc.get('x_elaslip_sources', [])
                
                # Add original source if not already in list
                if not sources and existing_doc.get('x_elaslip_import_job_id'):
                    sources.append({
                        'import_job_id': existing_doc.get('x_elaslip_import_job_id'),
                        'user_id': existing_doc.get('x_elaslip_created_by_user_id'),
                        'username': existing_doc.get('x_elaslip_created_by_username'),
                        'imported_at': existing_doc.get('created', datetime.utcnow().isoformat())
                    })
                
                # Add new source
                sources.append(source_info)
                
                # Update the document
                es.update('stix_relationships', rel_id, {
                    'doc': {
                        'x_elaslip_sources': sources,
                        'modified': datetime.utcnow().isoformat()
                    }
                })
                result['updated'] += 1
            else:
                # Create new relationship
                rel_doc = {
                    'id': rel_id,
                    'type': 'relationship',
                    'spec_version': rel.get('spec_version', '2.1'),
                    'created': rel.get('created', datetime.utcnow().isoformat()),
                    'modified': rel.get('modified', datetime.utcnow().isoformat()),
                    'relationship_type': rel['relationship_type'],
                    'source_ref': rel['source_ref'],
                    'target_ref': rel['target_ref'],
                    'description': rel.get('description'),
                    'x_elaslip_import_job_id': job_id,
                    'x_elaslip_created_by_user_id': user_id,
                    'x_elaslip_created_by_username': username,
                    'x_elaslip_sources': [source_info]
                }
                
                es.index('stix_relationships', rel_id, rel_doc)
                result['added'] += 1
            
        except Exception as e:
            result['errors'] += 1
            result['error_details'].append({
                'type': 'relationship',
                'error': str(e),
                'source_ref': rel.get('source_ref', 'unknown'),
                'target_ref': rel.get('target_ref', 'unknown')
            })
    
    return result


def import_stix_objects(es: ElasticsearchService, objects: List[Dict], 
                        user_id: str, username: str, job_id: str) -> Dict:
    """
    Import STIX domain objects (malware, threat-actor, etc.) with deduplication.
    
    If an object with the same ID already exists, adds the new source
    to the existing sources list instead of creating a duplicate.
    
    Returns:
        Dict with 'added', 'updated', 'errors', 'error_details'
    """
    result = {'added': 0, 'updated': 0, 'errors': 0, 'error_details': []}
    
    for obj in objects:
        try:
            obj_type = obj.get('type', 'unknown')
            obj_id = obj.get('id', f"{obj_type}--{__import__('uuid').uuid4()}")
            
            # Build source info for this import
            source_info = {
                'import_job_id': job_id,
                'user_id': user_id,
                'username': username,
                'imported_at': datetime.utcnow().isoformat()
            }
            
            # Check if object already exists
            existing = None
            try:
                existing = es.get('stix_objects', obj_id)
            except Exception:
                pass
            
            if existing and existing.get('_source'):
                # Update existing - merge sources
                existing_doc = existing['_source']
                sources = existing_doc.get('x_elaslip_sources', [])
                
                # Add original source if not already in list
                if not sources and existing_doc.get('x_elaslip_import_job_id'):
                    sources.append({
                        'import_job_id': existing_doc.get('x_elaslip_import_job_id'),
                        'user_id': existing_doc.get('x_elaslip_created_by_user_id'),
                        'username': existing_doc.get('x_elaslip_created_by_username'),
                        'imported_at': existing_doc.get('created', datetime.utcnow().isoformat())
                    })
                
                # Add new source
                sources.append(source_info)
                
                # Update the document
                es.update('stix_objects', obj_id, {
                    'doc': {
                        'x_elaslip_sources': sources,
                        'modified': datetime.utcnow().isoformat()
                    }
                })
                result['updated'] += 1
            else:
                # Create new object with metadata
                obj['x_elaslip_import_job_id'] = job_id
                obj['x_elaslip_created_by_user_id'] = user_id
                obj['x_elaslip_created_by_username'] = username
                obj['x_elaslip_sources'] = [source_info]
                
                # Ensure required fields
                if 'spec_version' not in obj:
                    obj['spec_version'] = '2.1'
                if 'created' not in obj:
                    obj['created'] = datetime.utcnow().isoformat()
                if 'modified' not in obj:
                    obj['modified'] = datetime.utcnow().isoformat()
                
                # Store in Elasticsearch
                es.index('stix_objects', obj_id, obj)
                result['added'] += 1
            
        except Exception as e:
            result['errors'] += 1
            result['error_details'].append({
                'type': obj.get('type', 'unknown'),
                'name': obj.get('name', 'unknown'),
                'error': str(e)
            })
    
    return result


def create_ioc_from_indicator(ioc_service: IOCService, indicator, source: Dict):
    """Create IOC from parsed indicator."""
    if isinstance(indicator, STIXIndicator):
        # Already a STIX indicator
        return ioc_service.create_from_pattern(
            pattern=indicator.pattern,
            labels=indicator.labels,
            source=source,
            name=indicator.indicator.name if hasattr(indicator.indicator, 'name') else None,
            description=indicator.indicator.description if hasattr(indicator.indicator, 'description') else None
        )
    elif isinstance(indicator, dict):
        # Dictionary with type and value
        return ioc_service.create(
            ioc_type=indicator['type'],
            value=indicator['value'],
            labels=indicator.get('labels', []),
            source=source,
            name=indicator.get('name'),
            description=indicator.get('description')
        )
    else:
        raise ValueError(f'Unknown indicator format: {type(indicator)}')


def update_job_status(es: ElasticsearchService, job_id: str, status: str):
    """Update job status."""
    es.update('import_jobs', job_id, {
        'doc': {
            'status': status,
            'updated_at': datetime.utcnow().isoformat()
        }
    })


def update_job_progress(es: ElasticsearchService, job_id: str, progress: int, 
                        total: int, processed: int = 0):
    """Update job progress."""
    es.update('import_jobs', job_id, {
        'doc': {
            'progress': progress,
            'total_items': total,
            'processed_items': processed,
            'updated_at': datetime.utcnow().isoformat()
        }
    })


def update_job_completed(es: ElasticsearchService, job_id: str, result: Dict):
    """Mark job as completed."""
    es.update('import_jobs', job_id, {
        'doc': {
            'status': 'completed',
            'progress': 100,
            'processed_items': result['added'] + result['duplicates'] + result['errors'],
            'added': result['added'],
            'updated': result['updated'],
            'duplicates': result['duplicates'],
            'errors': result['errors'],
            'error_details': result['error_details'][:100],  # Limit error details
            'completed_at': datetime.utcnow().isoformat()
        }
    })


def update_job_failed(es: ElasticsearchService, job_id: str, error: str, result: Dict):
    """Mark job as failed."""
    es.update('import_jobs', job_id, {
        'doc': {
            'status': 'failed',
            'error_message': error,
            'added': result.get('added', 0),
            'updated': result.get('updated', 0),
            'duplicates': result.get('duplicates', 0),
            'errors': result.get('errors', 0),
            'error_details': result.get('error_details', [])[:100],
            'completed_at': datetime.utcnow().isoformat()
        }
    })


def trigger_import_webhook(job_id: str, result: Dict):
    """Trigger webhook for import completion."""
    from app.tasks.webhook_tasks import dispatch_webhook
    try:
        dispatch_webhook.delay('import.completed', {
            'job_id': job_id,
            'result': result
        })
    except Exception:
        pass
