"""Scan Tasks for Celery - Batch scan processing with workers."""

import uuid
import logging
from datetime import datetime
from typing import Dict, List

from app import celery
from app.services.elasticsearch_service import ElasticsearchService
from app.services.tools_service import ToolsService

logger = logging.getLogger('celery.tasks')


def _save_task_result(es: ElasticsearchService, scan_id: str, tool: str, target: str, 
                      user_id: str, result: dict, extra_fields: dict = None) -> str:
    """
    Helper to save scan results to Elasticsearch.
    
    Args:
        es: ElasticsearchService instance
        scan_id: Unique scan ID
        tool: Tool name
        target: Scan target
        user_id: User ID who initiated
        result: Scan result
        extra_fields: Additional fields to include
    
    Returns:
        scan_id
    """
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'scan_id': scan_id,
        'user_id': user_id,
        'tool': tool,
        'target': target,
        'status': 'completed' if result.get('success') else 'failed',
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    if extra_fields:
        scan_doc.update(extra_fields)
    
    es.index('scan_results', scan_id, scan_doc)
    return scan_id


def _init_scan_doc(es: ElasticsearchService, scan_id: str, tool: str, target: str, 
                   user_id: str, extra_fields: dict = None) -> dict:
    """
    Initialize a scan document with processing status.
    """
    scan_doc = {
        'scan_id': scan_id,
        'user_id': user_id,
        'tool': tool,
        'target': target,
        'status': 'processing',
        'success': False,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    if extra_fields:
        scan_doc.update(extra_fields)
    
    try:
        es.index('scan_results', scan_id, scan_doc)
    except Exception as e:
        logger.warning(f"[{tool.upper()}] Could not save initial scan doc: {e}")
    
    return scan_doc


# ============================================================================
# Individual Async Scan Tasks
# ============================================================================

@celery.task(bind=True, max_retries=2, soft_time_limit=60)
def whois_async(self, scan_id: str, target: str, user_id: str):
    """
    Perform WHOIS lookup asynchronously.
    """
    logger.info(f"[WHOIS] Starting lookup for: {target} (scan_id: {scan_id})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'whois', target, user_id)
    
    try:
        result = tools.whois_lookup(target)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'whois', target, user_id, result)
        logger.info(f"[WHOIS] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[WHOIS] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'whois', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=60)
def ping_async(self, scan_id: str, target: str, user_id: str, count: int = 4):
    """
    Perform ICMP ping asynchronously.
    """
    logger.info(f"[PING] Starting ping to: {target} (scan_id: {scan_id}, count: {count})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'ping', target, user_id, {'count': count})
    
    try:
        result = tools.ping(target, count)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'ping', target, user_id, result, {'count': count})
        logger.info(f"[PING] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[PING] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'ping', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=900)
def nmap_async(self, scan_id: str, target: str, user_id: str, scan_type: str = 'quick',
               ports: str = None, custom_args: str = None):
    """
    Perform Nmap scan asynchronously.
    Extended timeout for full port scans.
    """
    logger.info(f"[NMAP] Starting scan: {target} (scan_id: {scan_id}, type: {scan_type}, ports: {ports})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    extra = {'scan_type': scan_type}
    if ports:
        extra['ports'] = ports
    if custom_args:
        extra['custom_args'] = custom_args
    
    _init_scan_doc(es, scan_id, 'nmap', target, user_id, extra)
    
    try:
        result = tools.nmap_scan(target, scan_type, ports, custom_args)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'nmap', target, user_id, result, extra)
        logger.info(f"[NMAP] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[NMAP] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'nmap', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=180)
def traceroute_async(self, scan_id: str, target: str, user_id: str, max_hops: int = 30):
    """
    Perform traceroute asynchronously.
    """
    logger.info(f"[TRACEROUTE] Starting trace to: {target} (scan_id: {scan_id}, max_hops: {max_hops})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'traceroute', target, user_id, {'max_hops': max_hops})
    
    try:
        result = tools.traceroute(target, max_hops)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'traceroute', target, user_id, result, {'max_hops': max_hops})
        logger.info(f"[TRACEROUTE] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[TRACEROUTE] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'traceroute', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=60)
def dig_async(self, scan_id: str, target: str, user_id: str, record_type: str = 'A'):
    """
    Perform DNS lookup using dig asynchronously.
    """
    logger.info(f"[DIG] Starting lookup: {target} (scan_id: {scan_id}, type: {record_type})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'dig', target, user_id, {'record_type': record_type})
    
    try:
        result = tools.dig_lookup(target, record_type)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'dig', target, user_id, result, {'record_type': record_type})
        logger.info(f"[DIG] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[DIG] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'dig', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=60)
def reverse_dns_async(self, scan_id: str, target: str, user_id: str):
    """
    Perform reverse DNS lookup asynchronously.
    """
    logger.info(f"[REVERSE-DNS] Starting lookup: {target} (scan_id: {scan_id})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'reverse-dns', target, user_id)
    
    try:
        result = tools.reverse_dns(target)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'reverse-dns', target, user_id, result)
        logger.info(f"[REVERSE-DNS] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[REVERSE-DNS] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'reverse-dns', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=300)
def dmarc_dkim_async(self, scan_id: str, target: str, user_id: str):
    """
    Analyze DMARC/DKIM/SPF records for a domain asynchronously.
    """
    logger.info(f"[DMARC/DKIM] Starting analysis: {target} (scan_id: {scan_id})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'dmarc-dkim', target, user_id)
    
    try:
        result = tools.analyze_dmarc_dkim(target)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'dmarc-dkim', target, user_id, result)
        logger.info(f"[DMARC/DKIM] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[DMARC/DKIM] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'dmarc-dkim', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=60)
def geoip_async(self, scan_id: str, target: str, user_id: str):
    """
    Perform GeoIP lookup asynchronously.
    """
    logger.info(f"[GEOIP] Starting lookup: {target} (scan_id: {scan_id})")
    
    es = ElasticsearchService()
    
    from app.services.geoip_service import GeoIPService
    geoip = GeoIPService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'geoip', target, user_id)
    
    try:
        result = geoip.lookup(target)
        if result:
            result['success'] = True
        else:
            result = {'success': False, 'error': 'GeoIP lookup failed'}
        result['scan_id'] = scan_id
        result['target'] = target
        
        _save_task_result(es, scan_id, 'geoip', target, user_id, result)
        logger.info(f"[GEOIP] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[GEOIP] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id, 'target': target}
        _save_task_result(es, scan_id, 'geoip', target, user_id, error_result)
        return error_result


@celery.task(bind=True, max_retries=2, soft_time_limit=120)
def shodan_async(self, scan_id: str, target: str, user_id: str, query_type: str = 'host'):
    """
    Query Shodan asynchronously.
    """
    logger.info(f"[SHODAN] Starting query: {target} (scan_id: {scan_id}, type: {query_type})")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    # Initialize scan document
    _init_scan_doc(es, scan_id, 'shodan', target, user_id, {'query_type': query_type})
    
    try:
        # Get API key from Flask config
        from flask import current_app
        from app.config import Config
        
        try:
            shodan_api_key = current_app.config.get('SHODAN_API_KEY') or Config.SHODAN_API_KEY
        except RuntimeError:
            # Outside of app context, use config directly
            shodan_api_key = Config.SHODAN_API_KEY
        
        if not shodan_api_key:
            raise ValueError("Shodan API key not configured")
        
        result = tools.shodan_query(target, shodan_api_key)
        result['scan_id'] = scan_id
        
        _save_task_result(es, scan_id, 'shodan', target, user_id, result, {'query_type': query_type})
        logger.info(f"[SHODAN] Completed for {target} (success: {result.get('success')})")
        
        return result
        
    except Exception as e:
        logger.error(f"[SHODAN] Error for {target}: {e}", exc_info=True)
        error_result = {'success': False, 'error': str(e), 'scan_id': scan_id}
        _save_task_result(es, scan_id, 'shodan', target, user_id, error_result)
        return error_result


# ============================================================================
# Generic Scan Status Check
# ============================================================================

def get_scan_status(scan_id: str) -> dict:
    """
    Get the status of any scan task.
    
    Args:
        scan_id: Scan ID to check
        
    Returns:
        Scan status and result if available
    """
    es = ElasticsearchService()
    
    try:
        result = es.get('scan_results', scan_id)
        if result:
            doc = result['_source']
            return {
                'scan_id': scan_id,
                'status': doc.get('status', 'unknown'),
                'success': doc.get('success', False),
                'tool': doc.get('tool'),
                'target': doc.get('target'),
                'result': doc.get('result'),
                'created_at': doc.get('created_at'),
                'updated_at': doc.get('updated_at')
            }
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
    
    return {
        'scan_id': scan_id,
        'status': 'not_found',
        'error': 'Scan not found'
    }


# ============================================================================
# Batch Processing (Legacy)
# ============================================================================
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


@celery.task(bind=True, soft_time_limit=300)
def analyze_dmarc_dkim_async(self, domain: str, user_id: str):
    """
    Analyze DMARC/DKIM/SPF records for a domain asynchronously.
    
    Args:
        domain: Domain to analyze
        user_id: User ID who initiated the analysis
    """
    import logging
    logger = logging.getLogger('celery.tasks')
    
    logger.info(f"[DMARC/DKIM] Task started for domain: {domain}")
    
    es = ElasticsearchService()
    tools = ToolsService()
    
    try:
        # Perform the analysis
        logger.info(f"[DMARC/DKIM] Analyzing domain {domain}...")
        result = tools.analyze_dmarc_dkim(domain)
        logger.info(f"[DMARC/DKIM] Analysis completed for {domain}. Success: {result.get('success', False)}")
        
        # Save to Elasticsearch
        logger.info(f"[DMARC/DKIM] Saving results to Elasticsearch...")
        scan_id = str(uuid.uuid4())
        
        result_copy = dict(result)
        result_copy.pop('raw_output', None)
        result_copy.pop('timestamp', None)
        
        scan_doc = {
            'user_id': user_id,
            'tool': 'dmarc-dkim',
            'target': domain,
            'success': result.get('success', False),
            'result': result_copy,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        es.index('scan_results', scan_id, scan_doc)
        logger.info(f"[DMARC/DKIM] Results saved with scan_id: {scan_id}")
        
        result['scan_id'] = scan_id
        
        logger.info(f"[DMARC/DKIM] Task completed successfully for {domain}")
        return result
        
    except Exception as e:
        logger.error(f"[DMARC/DKIM] Task failed for {domain}: {str(e)}", exc_info=True)
        return {'error': str(e), 'success': False}
