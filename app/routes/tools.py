"""Tools routes for WHOIS, Nmap, and other reconnaissance tools."""

import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.tools_service import ToolsService
from app.services.elasticsearch_service import ElasticsearchService

tools_bp = Blueprint('tools', __name__)


@tools_bp.route('/whois', methods=['POST'])
@login_or_api_key_required
def whois_lookup():
    """
    Perform WHOIS lookup.
    ---
    tags:
      - Tools
    summary: WHOIS Lookup
    requestBody:
      description: Target for WHOIS lookup
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: Domain name or IP address
              create_iocs:
                type: boolean
                description: Create IOCs from results
    responses:
      200:
        description: WHOIS lookup result
        schema:
          type: object
          properties:
            raw_output:
              type: string
            structured_data:
              type: object
      400:
        description: Invalid input
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Basic validation
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target. Must be a valid domain or IP address.'}), 400
    
    tools = ToolsService()
    result = tools.whois_lookup(target)
    
    # Save result to Elasticsearch
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    # Prepare document - keep raw_output for display
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': 'whois',
        'target': target,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    es.index('scan_results', scan_id, scan_doc)
    
    result['scan_id'] = scan_id
    return jsonify(result)


@tools_bp.route('/ping', methods=['POST'])
@login_or_api_key_required
def ping():
    """
    Perform ICMP ping.
    ---
    tags:
      - Tools
    summary: Ping Host
    requestBody:
      description: Target for ping
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: IP address or hostname
              count:
                type: integer
                default: 4
                description: Number of ping packets
    responses:
      200:
        description: Ping result
        schema:
          type: object
          properties:
            packets_sent:
              type: integer
            packets_received:
              type: integer
            packet_loss:
              type: string
            min_time:
              type: number
            avg_time:
              type: number
            max_time:
              type: number
      400:
        description: Invalid input
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    count = data.get('count', 4)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not isinstance(count, int) or count < 1 or count > 100:
        return jsonify({'error': 'Count must be between 1 and 100'}), 400
    
    # Basic validation
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target. Must be a valid domain or IP address.'}), 400
    
    tools = ToolsService()
    result = tools.ping(target, count)
    
    # Debug log
    import sys
    print(f"ROUTE PING: result keys = {result.keys()}, has raw_output = {'raw_output' in result}", file=sys.stderr)
    
    # Save result to Elasticsearch
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    # Prepare document
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': 'ping',
        'target': target,
        'count': count,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    es.index('scan_results', scan_id, scan_doc)
    
    result['scan_id'] = scan_id
    return jsonify(result)


@tools_bp.route('/nmap', methods=['POST'])
@login_or_api_key_required
def nmap_scan():
    """
    Perform Nmap scan.
    ---
    tags:
      - Tools
    summary: Nmap Scan
    requestBody:
      description: Nmap scan parameters
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)
              scan_type:
                type: string
                enum: [quick, full, service, vuln, traceroute, os, aggressive, custom]
                default: quick
                description: Predefined scan type
              ports:
                type: string
                description: Specific ports to scan (e.g., 22,80,443)
              custom_args:
                type: string
                description: Custom nmap arguments (for custom scan type)
              create_iocs:
                type: boolean
                description: Create IOCs from results
    responses:
      202:
        description: Scan started asynchronously
        schema:
          type: object
          properties:
            task_id:
              type: string
              description: Celery task ID for tracking progress
            message:
              type: string
      400:
        description: Invalid input
    """
    from app.tasks.scan_tasks import single_scan
    
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'quick')
    ports = data.get('ports')
    custom_args = data.get('custom_args')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    valid_types = ['quick', 'full', 'service', 'vuln', 'traceroute', 'os', 'aggressive', 'custom']
    if scan_type not in valid_types:
        return jsonify({'error': f'Invalid scan type. Use: {", ".join(valid_types)}'}), 400
    
    if scan_type == 'custom' and not custom_args:
        return jsonify({'error': 'custom_args is required for custom scan type'}), 400
    
    # Basic validation
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target. Must be a valid domain, IP, or CIDR range.'}), 400
    
    # Launch scan asynchronously via Celery
    task = single_scan.delay(
        tool='nmap',
        target=target,
        user_id=g.current_user.id,
        scan_type=scan_type,
        ports=ports,
        custom_args=custom_args
    )
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'nmap',
        'target': target,
        'scan_type': scan_type,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))  # Expire after 1 hour
    
    return jsonify({
        'task_id': task.id,
        'status': 'queued',
        'message': 'Nmap scan queued for processing'
    }), 202


@tools_bp.route('/traceroute', methods=['POST'])
@login_or_api_key_required
def traceroute():
    """
    Perform traceroute.
    ---
    tags:
      - Tools
    summary: Traceroute
    requestBody:
      description: Traceroute parameters
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: Target IP or hostname
              max_hops:
                type: integer
                default: 30
                description: Maximum number of hops
    responses:
      200:
        description: Traceroute result
        schema:
          type: object
          properties:
            hops:
              type: array
              items:
                type: object
            raw_output:
              type: string
      400:
        description: Invalid input
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    max_hops = data.get('max_hops', 30)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target.'}), 400
    
    tools = ToolsService()
    result = tools.traceroute(target, max_hops)
    
    # Save to ES
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': 'traceroute',
        'target': target,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    es.index('scan_results', scan_id, scan_doc)
    
    result['scan_id'] = scan_id
    return jsonify(result)


@tools_bp.route('/dig', methods=['POST'])
@login_or_api_key_required
def dig_lookup():
    """
    Perform DNS lookup using dig.
    ---
    tags:
      - Tools
    summary: DNS Lookup (dig)
    requestBody:
      description: DNS lookup parameters
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: Domain to lookup
              record_type:
                type: string
                enum: [A, AAAA, CNAME, MX, NS, TXT, SOA, ANY]
                default: A
                description: DNS record type
    responses:
      200:
        description: DNS lookup result
        schema:
          type: object
          properties:
            records:
              type: array
              items:
                type: object
            raw_output:
              type: string
      400:
        description: Invalid input
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    record_type = data.get('record_type', 'A')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    tools = ToolsService()
    result = tools.dig_lookup(target, record_type)
    
    # Save to ES
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': 'dig',
        'target': target,
        'record_type': record_type,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    es.index('scan_results', scan_id, scan_doc)
    
    result['scan_id'] = scan_id
    return jsonify(result)


@tools_bp.route('/reverse-dns', methods=['POST'])
@login_or_api_key_required
def reverse_dns():
    """
    Perform reverse DNS lookup.
    ---
    tags:
      - Tools
    summary: Reverse DNS Lookup
    requestBody:
      description: Reverse DNS lookup parameters
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - target
            properties:
              target:
                type: string
                description: IP address to lookup
    responses:
      200:
        description: Reverse DNS result
        schema:
          type: object
          properties:
            hostname:
              type: string
            raw_output:
              type: string
      400:
        description: Invalid input
    """
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    tools = ToolsService()
    result = tools.reverse_dns(target)
    
    # Save to ES
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': 'reverse-dns',
        'target': target,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    es.index('scan_results', scan_id, scan_doc)
    
    result['scan_id'] = scan_id
    return jsonify(result)


@tools_bp.route('/batch', methods=['POST'])
@login_or_api_key_required
def batch_scan():
    """
    Queue multiple scans for batch processing.
    ---
    tags:
      - Tools
    summary: Batch Scan Queue
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - scans
            properties:
              scans:
                type: array
                minItems: 1
                maxItems: 20
                items:
                  type: object
                  required:
                    - tool
                    - target
                  properties:
                    tool:
                      type: string
                      enum:
                        - whois
                        - ping
                        - nmap
                        - traceroute
                        - dig
                        - reverse_dns
                      description: Tool to use
                    target:
                      type: string
                      description: Target IP or domain
                    scan_type:
                      type: string
                      enum:
                        - quick
                        - standard
                        - aggressive
                      description: Nmap scan type (for nmap tool)
                    record_type:
                      type: string
                      enum:
                        - A
                        - AAAA
                        - CNAME
                        - MX
                        - NS
                        - TXT
                        - SOA
                        - ANY
                      description: DNS record type (for dig tool)
    responses:
      202:
        description: Scans queued for processing
        schema:
          type: object
          properties:
            job_id:
              type: string
              description: Batch job ID
            task_id:
              type: string
              description: Celery task ID
            status:
              type: string
              enum:
                - queued
            total_scans:
              type: integer
      400:
        description: Invalid request (no scans or too many scans)
    """
    data = request.get_json()
    scans = data.get('scans', [])
    
    if not scans:
        return jsonify({'error': 'No scans provided'}), 400
    
    if len(scans) > 20:
        return jsonify({'error': 'Maximum 20 scans per batch'}), 400
    
    # Queue the scans as a Celery task
    from app.tasks.scan_tasks import process_batch_scans
    
    job_id = str(uuid.uuid4())
    
    task = process_batch_scans.delay(
        job_id=job_id,
        user_id=g.current_user.id,
        scans=scans
    )
    
    return jsonify({
        'job_id': job_id,
        'task_id': task.id,
        'status': 'queued',
        'total_scans': len(scans)
    }), 202


@tools_bp.route('/scans', methods=['GET'])
@login_or_api_key_required
def list_scans():
    """
    List scan results.
    ---
    tags:
      - Tools
    summary: List Scans
    parameters:
      - in: query
        name: page
        schema:
          type: integer
          default: 1
        description: Page number
      - in: query
        name: per_page
        schema:
          type: integer
          default: 20
          maximum: 100
        description: Items per page
      - in: query
        name: tool
        schema:
          type: string
          enum: [whois, ping, nmap, traceroute, dig, reverse-dns]
        description: Filter by tool
    responses:
      200:
        description: List of scans
        schema:
          type: object
          properties:
            items:
              type: array
              items:
                type: object
            total:
              type: integer
            page:
              type: integer
    """
    es = ElasticsearchService()
    
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    tool_filter = request.args.get('tool')
    
    from_idx = (page - 1) * per_page
    
    query = {'term': {'user_id': g.current_user.id}}
    
    if tool_filter:
        query = {
            'bool': {
                'must': [
                    {'term': {'user_id': g.current_user.id}},
                    {'term': {'tool': tool_filter}}
                ]
            }
        }
    
    result = es.search('scan_results', {
        'query': query,
        'from': from_idx,
        'size': per_page,
        'sort': [{'timestamp': {'order': 'desc'}}]
    })
    
    scans = []
    for hit in result['hits']['hits']:
        scan = hit['_source']
        scan['id'] = hit['_id']
        scans.append(scan)
    
    return jsonify({
        'items': scans,
        'total': result['hits']['total']['value'],
        'page': page,
        'per_page': per_page
    })


@tools_bp.route('/scans/<scan_id>', methods=['GET'])
@login_or_api_key_required
def get_scan(scan_id):
    """
    Get a specific scan result.
    ---
    tags:
      - Tools
    summary: Get Scan Result
    parameters:
      - in: path
        name: scan_id
        required: true
        schema:
          type: string
        description: Scan ID
    responses:
      200:
        description: Scan result details
        schema:
          type: object
      404:
        description: Scan not found
    """
    es = ElasticsearchService()
    
    result = es.get('scan_results', scan_id)
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = result['_source']
    
    if scan['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    # Flatten the structure - move nested 'result' fields to root level for frontend compatibility
    if 'result' in scan:
        nested_result = scan.pop('result')
        scan.update(nested_result)
    
    scan['id'] = scan_id
    return jsonify(scan)


@tools_bp.route('/scans/<scan_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_scan(scan_id):
    """
    Delete a scan result.
    ---
    tags:
      - Tools
    summary: Delete Scan
    parameters:
      - in: path
        name: scan_id
        required: true
        schema:
          type: string
        description: Scan ID
    responses:
      200:
        description: Scan deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      404:
        description: Scan not found
    """
    es = ElasticsearchService()
    
    result = es.get('scan_results', scan_id)
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = result['_source']
    
    if scan['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    es.delete('scan_results', scan_id)
    
    return jsonify({'success': True})


@tools_bp.route('/scans/clear', methods=['DELETE'])
@login_or_api_key_required
def clear_scans():
    """
    Clear all scan history.
    ---
    tags:
      - Tools
    summary: Clear All Scans
    responses:
      200:
        description: All scans cleared
        schema:
          type: object
          properties:
            message:
              type: string
            deleted_count:
              type: integer
    """
    es = ElasticsearchService()
    
    # Delete all scans for this user
    try:
        index_name = es._get_index_name('scan_results')
        es._client.delete_by_query(
            index=index_name,
            body={
                'query': {
                    'term': {'user_id': g.current_user.id}
                }
            },
            refresh=True,
            ignore=[404]  # Ignore if index doesn't exist
        )
        return jsonify({'success': True, 'message': 'Scan history cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _is_valid_target(target: str) -> bool:
    """Basic validation for scan targets."""
    import re
    
    # IP address
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # CIDR notation
    cidr_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{1,2}$'
    
    # Domain name
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(ip_pattern, target):
        return True
    if re.match(cidr_pattern, target):
        return True
    if re.match(domain_pattern, target):
        return True
    
    return False


@tools_bp.route('/queue', methods=['GET'])
@login_or_api_key_required
def get_scan_queue():
    """
    Get current scan queue status.
    ---
    tags:
      - Tools
    summary: Get Scan Queue
    responses:
      200:
        description: Current scan queue status
        schema:
          type: array
          items:
            type: object
            properties:
              task_id:
                type: string
                description: Celery task ID
              worker:
                type: string
                description: Worker name
              status:
                type: string
                enum:
                  - running
                  - queued
              name:
                type: string
                description: Tool name
              target:
                type: string
                description: Target being scanned
              started_at:
                type: number
                description: Unix timestamp when task started
    """
    from app import celery as celery_app, redis_client
    import json
    
    # Get all active tasks
    inspect = celery_app.control.inspect()
    active = inspect.active() or {}
    
    # Filter tasks for current user
    user_scans = []
    for worker, tasks in active.items():
        for task in tasks:
            # Check if it's a scan task
            if 'process_batch_scans' in task['name'] or 'single_scan' in task['name']:
                task_id = task['id']
                
                # Try to get metadata from Redis
                task_meta = None
                try:
                    meta_key = f"scan_task:{task_id}"
                    meta_json = redis_client.get(meta_key)
                    if meta_json:
                        task_meta = json.loads(meta_json)
                except:
                    pass
                
                # Build task info
                task_info = {
                    'task_id': task_id,
                    'worker': worker,
                    'status': 'running',
                    'started_at': task.get('time_start')
                }
                
                # Use metadata if available
                if task_meta:
                    task_info['name'] = task_meta.get('tool', 'scan')
                    task_info['target'] = task_meta.get('target', '')
                    task_info['scan_type'] = task_meta.get('scan_type', '')
                else:
                    task_info['name'] = task['name'].split('.')[-1]
                
                user_scans.append(task_info)
    
    # Get reserved tasks (waiting to be processed)
    reserved = inspect.reserved() or {}
    for worker, tasks in reserved.items():
        for task in tasks:
            if 'process_batch_scans' in task['name'] or 'single_scan' in task['name']:
                task_id = task['id']
                
                # Try to get metadata from Redis
                task_meta = None
                try:
                    meta_key = f"scan_task:{task_id}"
                    meta_json = redis_client.get(meta_key)
                    if meta_json:
                        task_meta = json.loads(meta_json)
                except:
                    pass
                
                task_info = {
                    'task_id': task_id,
                    'worker': worker,
                    'status': 'queued'
                }
                
                # Use metadata if available
                if task_meta:
                    task_info['name'] = task_meta.get('tool', 'scan')
                    task_info['target'] = task_meta.get('target', '')
                    task_info['scan_type'] = task_meta.get('scan_type', '')
                else:
                    task_info['name'] = task['name'].split('.')[-1]
                
                user_scans.append(task_info)
    
    return jsonify({
        'queue': user_scans,
        'total': len(user_scans)
    })


@tools_bp.route('/task/<task_id>', methods=['GET'])
@login_or_api_key_required
def get_task_status(task_id):
    """
    Get status of a specific task.
    ---
    tags:
      - Tools
    summary: Get Task Status
    parameters:
      - in: path
        name: task_id
        schema:
          type: string
        required: true
        description: Celery task ID
    responses:
      200:
        description: Task status details
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
              enum:
                - PENDING
                - STARTED
                - SUCCESS
                - FAILURE
                - RETRY
                - REVOKED
            result:
              type: object
              description: Task result (if successful)
            error:
              type: string
              description: Error message (if failed)
    """
    from app import celery as celery_app
    from celery.result import AsyncResult
    
    result = AsyncResult(task_id, app=celery_app)
    
    return jsonify({
        'task_id': task_id,
        'status': result.status,
        'result': result.result if result.successful() else None,
        'error': str(result.info) if result.failed() else None
    })
