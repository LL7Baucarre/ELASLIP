"""Scan Tasks for Celery - Batch scan processing with workers."""

import uuid
from datetime import datetime
from typing import Dict, List

from app import celery
from app.services.elasticsearch_service import ElasticsearchService
from app.services.tools_service import ToolsService


@celery.task(bind=True, max_retries=3, soft_time_limit=300)
def process_batch_scans(self, job_id: str, user_id: str, scans: List[Dict]):
    """
    Process multiple scans in batch.
    
    Args:
        job_id: Batch job ID
        user_id: User ID who initiated the batch
        scans: List of scan configurations
            Each scan should have:
            - tool: whois, nmap, traceroute, dig, reverse-dns
            - target: target IP/domain
            - Additional params depending on tool
    """
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Create job record
    job_doc = {
        'job_id': job_id,
        'user_id': user_id,
        'status': 'processing',
        'total': len(scans),
        'completed': 0,
        'successful': 0,
        'failed': 0,
        'results': [],
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    try:
        es.index('batch_jobs', job_id, job_doc)
    except Exception:
        # Index might not exist, create it
        pass
    
    results = []
    
    for i, scan_config in enumerate(scans):
        tool = scan_config.get('tool', '').lower()
        target = scan_config.get('target', '').strip()
        
        scan_result = {
            'index': i,
            'tool': tool,
            'target': target,
            'success': False,
            'error': None,
            'scan_id': None
        }
        
        if not target:
            scan_result['error'] = 'Target is required'
            results.append(scan_result)
            job_doc['failed'] += 1
            continue
        
        try:
            result = None
            
            if tool == 'whois':
                result = tools.whois_lookup(target)
                
            elif tool == 'nmap':
                scan_type = scan_config.get('scan_type', 'quick')
                ports = scan_config.get('ports')
                custom_args = scan_config.get('custom_args')
                result = tools.nmap_scan(target, scan_type, ports, custom_args)
                
            elif tool == 'traceroute':
                max_hops = scan_config.get('max_hops', 30)
                result = tools.traceroute(target, max_hops)
                
            elif tool == 'dig':
                record_type = scan_config.get('record_type', 'A')
                result = tools.dig_lookup(target, record_type)
                
            elif tool == 'reverse-dns':
                result = tools.reverse_dns(target)
                
            else:
                scan_result['error'] = f'Unknown tool: {tool}'
                results.append(scan_result)
                job_doc['failed'] += 1
                continue
            
            if result:
                # Save to Elasticsearch
                scan_id = str(uuid.uuid4())
                
                result_copy = dict(result)
                result_copy.pop('raw_output', None)
                result_copy.pop('timestamp', None)
                
                scan_doc = {
                    'user_id': user_id,
                    'tool': tool,
                    'target': target,
                    'success': result.get('success', False),
                    'result': result_copy,
                    'batch_job_id': job_id,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                
                # Add tool-specific fields
                if tool == 'nmap':
                    scan_doc['scan_type'] = scan_config.get('scan_type', 'quick')
                    scan_doc['ports'] = scan_config.get('ports')
                    scan_doc['custom_args'] = scan_config.get('custom_args')
                elif tool == 'dig':
                    scan_doc['record_type'] = scan_config.get('record_type', 'A')
                
                es.index('scan_results', scan_id, scan_doc)
                
                scan_result['success'] = result.get('success', False)
                scan_result['scan_id'] = scan_id
                
                if result.get('success'):
                    job_doc['successful'] += 1
                else:
                    scan_result['error'] = result.get('error')
                    job_doc['failed'] += 1
                
        except Exception as e:
            scan_result['error'] = str(e)
            job_doc['failed'] += 1
        
        results.append(scan_result)
        job_doc['completed'] += 1
        job_doc['results'] = results
        job_doc['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        # Update job progress
        try:
            es.index('batch_jobs', job_id, job_doc)
        except Exception:
            pass
    
    # Finalize job
    job_doc['status'] = 'completed'
    job_doc['updated_at'] = datetime.utcnow().isoformat() + 'Z'
    job_doc['results'] = results
    
    try:
        es.index('batch_jobs', job_id, job_doc)
    except Exception:
        pass
    
    return {
        'job_id': job_id,
        'status': 'completed',
        'total': len(scans),
        'successful': job_doc['successful'],
        'failed': job_doc['failed']
    }


@celery.task(bind=True)
def single_scan(self, tool: str, target: str, user_id: str, **kwargs):
    """
    Process a single scan asynchronously.
    Useful for long-running scans like vulnerability scans.
    """
    es = ElasticsearchService()
    tools = ToolsService()
    
    result = None
    
    try:
        if tool == 'whois':
            result = tools.whois_lookup(target)
            
        elif tool == 'nmap':
            scan_type = kwargs.get('scan_type', 'quick')
            ports = kwargs.get('ports')
            custom_args = kwargs.get('custom_args')
            result = tools.nmap_scan(target, scan_type, ports, custom_args)
            
        elif tool == 'traceroute':
            max_hops = kwargs.get('max_hops', 30)
            result = tools.traceroute(target, max_hops)
            
        elif tool == 'dig':
            record_type = kwargs.get('record_type', 'A')
            result = tools.dig_lookup(target, record_type)
            
        elif tool == 'reverse-dns':
            result = tools.reverse_dns(target)
            
        else:
            return {'error': f'Unknown tool: {tool}', 'success': False}
        
        if result:
            # Save to Elasticsearch
            scan_id = str(uuid.uuid4())
            
            result_copy = dict(result)
            result_copy.pop('raw_output', None)
            result_copy.pop('timestamp', None)
            
            scan_doc = {
                'user_id': user_id,
                'tool': tool,
                'target': target,
                'success': result.get('success', False),
                'result': result_copy,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            es.index('scan_results', scan_id, scan_doc)
            
            result['scan_id'] = scan_id
            
        return result
        
    except Exception as e:
        return {'error': str(e), 'success': False}
