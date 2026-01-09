"""Tools routes for WHOIS, Nmap, and other reconnaissance tools."""

import uuid
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, g, current_app

from app.auth import login_or_api_key_required
from app.decorators import permission_required
from app.services.tools_service import ToolsService
from app.services.elasticsearch_service import ElasticsearchService
from app.utils.request_helpers import get_pagination_params, build_filters_dict
import logging
logger = logging.getLogger(__name__)

tools_bp = Blueprint('tools', __name__)


@tools_bp.route('/worker/public-ip', methods=['GET'])
@login_or_api_key_required
def get_worker_public_ip():
    """
    Get the public IP address of the worker and VPN status.
    This endpoint is public to allow dashboard widgets to load it.
    
    Returns:
        Dict with public IP information and VPN status
    """
    from app.tasks.scan_tasks import get_worker_public_ip_async
    from app import celery
    import os
    
    result = {
        'success': False,
        'ip': None,
        'vpn_enabled': os.environ.get('VPN_ENABLED', 'false').lower() == 'true',
        'vpn_status': None
    }
    
    try:
        # Get worker public IP
        worker_result = get_worker_public_ip_async.apply_async(timeout=10)
        ip_data = worker_result.get(timeout=10)
        result.update(ip_data)
        
        # Determine VPN status based on response
        if result['vpn_enabled']:
            # If we got response from gluetun-vpn service, it means VPN is active
            if ip_data.get('service') == 'gluetun-vpn':
                result['vpn_status'] = 'running'
            else:
                result['vpn_status'] = 'not_running'
        
        result['success'] = True
    except Exception as e:
        result['error'] = str(e)
    
    return jsonify(result)


def _save_scan_result(tool_name: str, target: str, result: dict, extra_fields: dict = None) -> str:
    """
    Helper method to save scan results to Elasticsearch.
    Reduces code duplication across tool endpoints.
    
    Args:
        tool_name: Name of the tool (whois, ping, nmap, etc.)
        target: Target of the scan
        result: Result data from the tool
        extra_fields: Optional dict with additional scan metadata fields
    
    Returns:
        scan_id: ID of the saved scan
    """
    es = ElasticsearchService()
    scan_id = str(uuid.uuid4())
    
    # Prepare document - remove timestamp to avoid duplication
    result_copy = dict(result)
    result_copy.pop('timestamp', None)
    
    scan_doc = {
        'user_id': g.current_user.id,
        'tool': tool_name,
        'target': target,
        'success': result.get('success', False),
        'result': result_copy,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    # Add extra metadata fields if provided
    if extra_fields:
        scan_doc.update(extra_fields)
    
    es.index('scan_results', scan_id, scan_doc)
    return scan_id


@tools_bp.route('/whois', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import whois_async
    
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Basic validation
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target. Must be a valid domain or IP address.'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = whois_async.delay(scan_id, target, g.current_user.id)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'whois',
        'target': target,
        'scan_id': scan_id,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'WHOIS lookup queued for processing'
    }), 202


@tools_bp.route('/ping', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import ping_async
    
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
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = ping_async.delay(scan_id, target, g.current_user.id, count)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'ping',
        'target': target,
        'scan_id': scan_id,
        'count': count,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'Ping queued for processing'
    }), 202


@tools_bp.route('/nmap', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import nmap_async
    
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
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = nmap_async.delay(scan_id, target, g.current_user.id, scan_type, ports, custom_args)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'nmap',
        'target': target,
        'scan_id': scan_id,
        'scan_type': scan_type,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'Nmap scan queued for processing'
    }), 202


@tools_bp.route('/traceroute', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import traceroute_async
    
    data = request.get_json()
    target = data.get('target', '').strip()
    max_hops = data.get('max_hops', 30)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target.'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = traceroute_async.delay(scan_id, target, g.current_user.id, max_hops)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'traceroute',
        'target': target,
        'scan_id': scan_id,
        'max_hops': max_hops,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'Traceroute queued for processing'
    }), 202


@tools_bp.route('/dig', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import dig_async
    
    data = request.get_json()
    target = data.get('target', '').strip()
    record_type = data.get('record_type', 'A')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = dig_async.delay(scan_id, target, g.current_user.id, record_type)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'dig',
        'target': target,
        'scan_id': scan_id,
        'record_type': record_type,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'DNS lookup queued for processing'
    }), 202


@tools_bp.route('/reverse-dns', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    from app.tasks.scan_tasks import reverse_dns_async
    
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = reverse_dns_async.delay(scan_id, target, g.current_user.id)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'reverse-dns',
        'target': target,
        'scan_id': scan_id,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'Reverse DNS lookup queued for processing'
    }), 202

def _clean_email_address(email_str, all_emails=False):
    """
    Clean email address from headers (handle format: "Name <email@domain.com>" or variations).
    
    Args:
        email_str: Raw email address string from header
        all_emails: If True, return all emails as list; if False, return only first as string
    
    Returns:
        str or list: Cleaned email address(es)
    """
    import re
    
    if not email_str:
        return [] if all_emails else 'N/A'
    
    # Split by comma to get individual emails
    email_list = []
    for email_item in email_str.split(','):
        email_item = email_item.strip()
        
        # Handle "Name <email@domain.com>" format
        match = re.search(r'<(.+?)>', email_item)
        if match:
            email_list.append(match.group(1).strip())
        else:
            # If no angle brackets, use as-is
            email_list.append(email_item)
    
    if all_emails:
        return email_list if email_list else []
    else:
        return email_list[0] if email_list else 'N/A'


def _parse_email_headers(headers_text):
    """
    Parse email headers and extract key information.
    
    Args:
        headers_text: Raw email headers as string
    
    Returns:
        dict: Parsed header information with analysis
    """
    import re
    from email.parser import Parser
    from io import StringIO
    
    try:
        # Parse headers using email library
        parser = Parser()
        message = parser.parsestr(headers_text)
        
        # Extract key headers with cleaning
        extracted = {
            'from': _clean_email_address(message.get('From', 'N/A')),
            'to': _clean_email_address(message.get('To', 'N/A'), all_emails=True),
            'cc': _clean_email_address(message.get('Cc', 'N/A'), all_emails=True),
            'subject': message.get('Subject', 'N/A'),
            'date': message.get('Date', 'N/A'),
            'message_id': message.get('Message-ID', 'N/A'),
            'content_type': message.get('Content-Type', 'N/A'),
            'all_headers': dict(message)
        }
        
        # Parse hop information from Received headers
        hops = []
        received_headers = message.get_all('Received') or []
        
        for i, received in enumerate(reversed(received_headers)):
            hop = {
                'number': i + 1,
                'raw': received.strip(),
                'from': _extract_received_field(received, 'from'),
                'by': _extract_received_field(received, 'by'),
                'with': _extract_received_field(received, 'with'),
                'date': _extract_received_field(received, ';'),
            }
            hops.append(hop)
        
        # Extract source IP (from first hop)
        source_ip = None
        if hops:
            hop_data = hops[0]['raw']
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', hop_data)
            if ip_match:
                source_ip = ip_match.group(1)
        
        extracted['hops'] = hops
        extracted['source_ip'] = source_ip
        extracted['hop_count'] = len(hops)
        
        return {
            'success': True,
            'parsed': extracted,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }


def _extract_received_field(received_header, field_name):
    """
    Extract specific field from Received header.
    
    Args:
        received_header: Full Received header string
        field_name: Field to extract (from, by, with, ;)
    
    Returns:
        str: Extracted field value or None
    """
    import re
    
    field_map = {
        'from': r'from\s+([^\s]+)',
        'by': r'by\s+([^\s]+)',
        'with': r'with\s+([^\s]+)',
        ';': r';\s*(.+?)(?:$|(?=\n))'
    }
    
    pattern = field_map.get(field_name)
    if not pattern:
        return None
    
    match = re.search(pattern, received_header, re.IGNORECASE)
    return match.group(1) if match else None


@tools_bp.route('/email-headers', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def email_header_analyzer():
    """
    Analyze email headers and extract key information.
    ---
    tags:
      - Tools
    summary: Email Header Analysis
    requestBody:
      description: Email headers to analyze
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - headers
            properties:
              headers:
                type: string
                description: Raw email headers
    responses:
      200:
        description: Email header analysis result
        schema:
          type: object
          properties:
            success:
              type: boolean
            parsed:
              type: object
              properties:
                from:
                  type: string
                to:
                  type: string
                subject:
                  type: string
                hops:
                  type: array
                  items:
                    type: object
                source_ip:
                  type: string
      400:
        description: Invalid input
    """
    data = request.get_json()
    headers = data.get('headers', '').strip()
    
    if not headers:
        return jsonify({'error': 'Email headers are required'}), 400
    
    # Limit header size to 100KB
    if len(headers) > 102400:
        return jsonify({'error': 'Headers too large (max 100KB)'}), 400
    
    result = _parse_email_headers(headers)
    
    if result['success']:
        scan_id = _save_scan_result('email-headers', 'Email Analysis', result, {
            'source_ip': result['parsed'].get('source_ip'),
            'hop_count': result['parsed'].get('hop_count')
        })
        result['scan_id'] = scan_id
    
    return jsonify(result)


@tools_bp.route('/batch', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
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
    
    page, per_page = get_pagination_params(default_per_page=20)
    filters = build_filters_dict({'tool': None})
    
    from_idx = (page - 1) * per_page
    
    query = {'term': {'user_id': g.current_user.id}}
    
    if filters.get('tool'):
        query = {
            'bool': {
                'must': [
                    {'term': {'user_id': g.current_user.id}},
                    {'term': {'tool': filters['tool']}}
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


@tools_bp.route('/task/<task_id>', methods=['GET'])
@login_or_api_key_required
def get_task_status(task_id):
    """
    Get the status of an async task (Celery task).
    ---
    tags:
      - Tools
    summary: Get Task Status
    parameters:
      - in: path
        name: task_id
        required: true
        schema:
          type: string
        description: Celery task ID
    responses:
      200:
        description: Task status
        schema:
          type: object
          properties:
            task_id:
              type: string
            state:
              type: string
              enum: [PENDING, RETRY, FAILURE, SUCCESS]
            status:
              type: string
            result:
              type: object
      404:
        description: Task not found
    """
    from app import celery
    
    result = celery.AsyncResult(task_id)
    
    response = {
        'task_id': task_id,
        'state': result.state,
        'status': result.state
    }
    
    # Only include result if task is ready and successful
    if result.ready():
        if result.successful():
            response['result'] = result.result
        else:
            # For failed tasks, include error info
            response['error'] = str(result.info)
    
    return jsonify(response)


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
    
    # All async scan task names to track
    scan_task_names = [
        'whois_async', 'ping_async', 'nmap_async', 'traceroute_async', 
        'dig_async', 'reverse_dns_async', 'dmarc_dkim_async', 'geoip_async', 
        'shodan_async', 'scan_url', 'process_batch_scans', 'single_scan'
    ]
    
    # Filter tasks for current user
    user_scans = []
    for worker, tasks in active.items():
        for task in tasks:
            # Check if it's a scan task
            task_name = task['name'].split('.')[-1]
            if any(name in task['name'] for name in scan_task_names):
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
                    task_info['scan_id'] = task_meta.get('scan_id', '')
                else:
                    task_info['name'] = task_name
                
                user_scans.append(task_info)
    
    # Get reserved tasks (waiting to be processed)
    reserved = inspect.reserved() or {}
    for worker, tasks in reserved.items():
        for task in tasks:
            task_name = task['name'].split('.')[-1]
            if any(name in task['name'] for name in scan_task_names):
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
                    task_info['scan_id'] = task_meta.get('scan_id', '')
                else:
                    task_info['name'] = task_name
                
                user_scans.append(task_info)
    
    return jsonify({
        'queue': user_scans,
        'total': len(user_scans)
    })


@tools_bp.route('/geoip', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def geoip_lookup():
    """
    Perform GeoIP lookup on an IP address.
    
    ---
    tags:
      - Tools
    summary: GeoIP Lookup
    requestBody:
      description: IP address for GeoIP lookup
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - ip
            properties:
              ip:
                type: string
                description: IPv4 or IPv6 address to look up
    responses:
      200:
        description: GeoIP lookup result
        schema:
          type: object
          properties:
            ip:
              type: string
            continent:
              type: string
            country:
              type: string
            country_code:
              type: string
            city:
              type: string
            latitude:
              type: number
            longitude:
              type: number
            timezone:
              type: string
            isp:
              type: string
            organization:
              type: string
            asn:
              type: string
      400:
        description: Invalid IP address
    """
    from app.tasks.scan_tasks import geoip_async
    
    data = request.get_json()
    ip_address = data.get('target', '').strip()
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = geoip_async.delay(scan_id, ip_address, g.current_user.id)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'geoip',
        'target': ip_address,
        'scan_id': scan_id,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'GeoIP lookup queued for processing'
    }), 202


@tools_bp.route('/geoip/bulk', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def geoip_bulk_lookup():
    """
    Perform bulk GeoIP lookups.
    
    ---
    tags:
      - Tools
    summary: Bulk GeoIP Lookup
    requestBody:
      description: List of IP addresses
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - ips
            properties:
              ips:
                type: array
                items:
                  type: string
                description: List of IPv4 or IPv6 addresses
    responses:
      200:
        description: Bulk GeoIP lookup results
    """
    data = request.get_json()
    ips = data.get('targets', [])
    
    if not ips or not isinstance(ips, list):
        return jsonify({'error': 'List of IPs is required'}), 400
    
    if len(ips) > 100:
        return jsonify({'error': 'Maximum 100 IPs per request'}), 400
    
    try:
        from app.services.geoip_service import GeoIPService
        service = GeoIPService()
        results = service.bulk_lookup(ips)
        
        # Save scan result
        scan_id = _save_scan_result('geoip_bulk', f"{len(ips)} IPs", results, {
            'ip_count': len(ips)
        })
        results['scan_id'] = scan_id
        
        return jsonify(results), 200
    except Exception as e:
        current_app.logger.exception(f"Bulk GeoIP lookup error: {str(e)}")
        return jsonify({'error': 'Bulk GeoIP lookup failed'}), 500


@tools_bp.route('/file-analysis', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def analyze_file():
    """
    Analyze an uploaded file and extract hashes, metadata, and properties.
    
    Calculates MD5, SHA1, and SHA256 hashes. Extracts comprehensive file metadata including:
    file type detection, architecture detection, document metadata (PDF, Office), image EXIF data,
    and file entropy analysis. Scan results are automatically saved to history.
    
    ---
    tags:
      - Tools
    summary: File Analysis
    operationId: analyzeFile
    requestBody:
      description: File to analyze
      required: true
      content:
        multipart/form-data:
          schema:
            type: object
            required:
              - file
            properties:
              file:
                type: string
                format: binary
                description: File to analyze
    responses:
      200:
        description: File analysis result with hashes and metadata
        schema:
          type: object
          properties:
            success:
              type: boolean
            filename:
              type: string
            size:
              type: integer
            mime_type:
              type: string
            extension:
              type: string
            is_binary:
              type: boolean
            magic_signature:
              type: string
            hashes:
              type: object
              properties:
                md5:
                  type: string
                sha1:
                  type: string
                sha256:
                  type: string
            metadata:
              type: object
              properties:
                file_entropy:
                  type: number
                sections:
                  type: object
                properties:
                  type: object
            scan_id:
              type: string
      400:
        description: Invalid input or file too large
      401:
        description: Unauthorized
      403:
        description: Forbidden
    """
    # Check if file is in request
    if 'file' not in request.files:
        return jsonify({'error': 'File is required'}), 400
    
    file_obj = request.files['file']
    
    # Analyze the file
    service = ToolsService()
    result = service.analyze_file(file_obj)
    
    if not result.get('success'):
        return jsonify(result), 400
    
    # Save analysis result to Elasticsearch
    scan_id = _save_scan_result(
        'file-analysis',
        result.get('filename'),
        result,
        {'file_size': result.get('size')}
    )
    
    result['scan_id'] = scan_id
    
    return jsonify(result), 200


@tools_bp.route('/dmarc-dkim', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def analyze_dmarc_dkim():
    """
    Analyze DMARC, DKIM, and SPF records for a domain asynchronously.
    ---
    tags:
      - Tools
    summary: DMARC/DKIM/SPF Analysis
    requestBody:
      description: Domain to analyze
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - domain
            properties:
              domain:
                type: string
                description: Domain name to analyze
    responses:
      202:
        description: Analysis started asynchronously
        schema:
          type: object
          properties:
            task_id:
              type: string
              description: Celery task ID for tracking progress
            status:
              type: string
            message:
              type: string
      400:
        description: Invalid input
    """
    from app.tasks.scan_tasks import dmarc_dkim_async
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Basic domain validation
    if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    task = dmarc_dkim_async.delay(scan_id, domain, g.current_user.id)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'dmarc-dkim',
        'target': domain,
        'scan_id': scan_id,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'DMARC/DKIM analysis queued for processing'
    }), 202

@tools_bp.route('/shodan', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def query_shodan():
    """
    Search Shodan for internet-facing devices and services.
    ---
    tags:
      - Tools
    summary: Shodan Query
    requestBody:
      description: Shodan search query (IP address, hostname, query string)
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - query
            properties:
              query:
                type: string
                description: Search query (IP, domain, or Shodan filter query)
    responses:
      200:
        description: Shodan search results
        schema:
          type: object
          properties:
            success:
              type: boolean
            query:
              type: string
            type:
              type: string
              enum: [host, search]
            timestamp:
              type: string
            data:
              type: object
              description: Host data (for single IP)
            matches:
              type: array
              description: Search results (for query)
      400:
        description: Invalid input or missing API key
    """
    from app.config import Config
    from app.tasks.scan_tasks import shodan_async
    
    # Check if Shodan is enabled - first check runtime config (from settings), then fall back to environment
    shodan_api_key = current_app.config.get('SHODAN_API_KEY') or Config.SHODAN_API_KEY
    
    if not shodan_api_key:
        return jsonify({'error': 'Shodan API key not configured'}), 400
    
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({'error': 'Query is required'}), 400
    
    if len(query) > 500:
        return jsonify({'error': 'Query is too long (max 500 characters)'}), 400
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    
    # Determine query type (host lookup vs search)
    import ipaddress
    try:
        ipaddress.ip_address(query)
        query_type = 'host'
    except ValueError:
        query_type = 'search'
    
    task = shodan_async.delay(scan_id, query, g.current_user.id, query_type, shodan_api_key)
    
    # Store task metadata in Redis for queue display
    from app import redis_client
    import json
    task_key = f"scan_task:{task.id}"
    task_meta = {
        'tool': 'shodan',
        'target': query,
        'scan_id': scan_id,
        'query_type': query_type,
        'user_id': g.current_user.id,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    redis_client.setex(task_key, 3600, json.dumps(task_meta))
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'Shodan query queued for processing'
    }), 202


@tools_bp.route('/shodan/test', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def test_shodan():
    """
    Test Shodan API connection (synchronous, for testing API keys).
    ---
    tags:
      - Tools
    summary: Test Shodan Connection
    requestBody:
      description: API key to test
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - api_key
            properties:
              api_key:
                type: string
                description: Shodan API key to test
    responses:
      200:
        description: Connection test result
    """
    from app.services.tools_service import ToolsService
    
    data = request.get_json()
    api_key = data.get('api_key', '').strip()
    
    if not api_key:
        return jsonify({'success': False, 'error': 'API key is required'}), 400
    
    # Test with a simple query (Google DNS)
    tools = ToolsService()
    result = tools.shodan_query('8.8.8.8', api_key)
    
    return jsonify(result)


# ============================================================================
# URL Scan with Playwright
# ============================================================================

@tools_bp.route('/urlscan', methods=['POST'])
@login_or_api_key_required
@permission_required('tools.execute')
def start_urlscan():
    """
    Start a URL scan using Playwright to capture screenshot and extract links.
    ---
    tags:
      - Tools
    summary: URL Scan
    description: Scan a URL to capture a screenshot and extract visible links, metadata, and technologies
    requestBody:
      description: URL scan configuration
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - url
            properties:
              url:
                type: string
                description: URL to scan (must be http or https)
              viewport_width:
                type: integer
                default: 1920
                description: Browser viewport width
              viewport_height:
                type: integer
                default: 1080
                description: Browser viewport height
              wait_time:
                type: integer
                default: 2000
                description: Time to wait after page load (ms)
              full_page:
                type: boolean
                default: false
                description: Capture full page screenshot
    responses:
      202:
        description: Scan started
        schema:
          type: object
          properties:
            scan_id:
              type: string
            status:
              type: string
            message:
              type: string
      400:
        description: Invalid input
    """
    from urllib.parse import urlparse
    from app.tasks.urlscan_tasks import scan_url
    
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL format
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400
        if not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except Exception:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Prevent scanning internal/private IPs (basic check)
    netloc = parsed.netloc.lower()
    private_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
    for pattern in private_patterns:
        if netloc.startswith(pattern) or netloc == pattern.rstrip('.'):
            return jsonify({'error': 'Scanning private/internal addresses is not allowed'}), 400
    
    # Prepare scan options
    options = {
        'viewport_width': min(data.get('viewport_width', 1920), 3840),
        'viewport_height': min(data.get('viewport_height', 1080), 2160),
        'wait_time': min(data.get('wait_time', 2000), 10000),
        'full_page': data.get('full_page', False),
        'user_agent': data.get('user_agent')
    }
    
    # Generate scan ID and start async task
    scan_id = str(uuid.uuid4())
    
    # Queue the scan task
    task = scan_url.delay(scan_id, url, g.current_user.id, options)
    
    logger.info(f"[URLScan] Started scan for {url} (scan_id: {scan_id}, task_id: {task.id})")
    
    return jsonify({
        'scan_id': scan_id,
        'task_id': task.id,
        'status': 'queued',
        'message': 'URL scan started. Poll /api/tools/urlscan/<scan_id> for results.',
        'url': url
    }), 202


@tools_bp.route('/urlscan/<scan_id>', methods=['GET'])
@login_or_api_key_required
@permission_required('tools.execute')
def get_urlscan_result(scan_id: str):
    """
    Get URL scan result.
    ---
    tags:
      - Tools
    summary: Get URL Scan Result
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
        description: Scan ID
    responses:
      200:
        description: Scan result
        schema:
          type: object
          properties:
            scan_id:
              type: string
            status:
              type: string
              enum: [queued, processing, completed, failed]
            success:
              type: boolean
            url:
              type: string
            final_url:
              type: string
            screenshot:
              type: string
              description: Base64 encoded PNG screenshot
            links:
              type: object
            metadata:
              type: object
            technologies:
              type: array
      404:
        description: Scan not found
    """
    es = ElasticsearchService()
    
    try:
        result = es.get('scan_results', scan_id)
        if result:
            doc = result['_source']
            
            # Check if user owns this scan or is admin
            if doc.get('user_id') != g.current_user.id and not g.current_user.has_role('Admin'):
                return jsonify({'error': 'Access denied'}), 403
            
            return jsonify({
                'scan_id': scan_id,
                'status': doc.get('status', 'unknown'),
                'success': doc.get('success', False),
                'url': doc.get('url'),
                'result': doc.get('result'),
                'created_at': doc.get('created_at'),
                'updated_at': doc.get('updated_at')
            })
    except Exception as e:
        logger.error(f"[URLScan] Error getting scan result: {e}")
    
    return jsonify({'error': 'Scan not found'}), 404


@tools_bp.route('/urlscan/<scan_id>/screenshot', methods=['GET'])
@login_or_api_key_required
@permission_required('tools.execute')
def get_urlscan_screenshot(scan_id: str):
    """
    Get URL scan screenshot as image.
    ---
    tags:
      - Tools
    summary: Get URL Scan Screenshot
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
        description: Scan ID
    responses:
      200:
        description: PNG screenshot image
        content:
          image/png:
            schema:
              type: string
              format: binary
      404:
        description: Screenshot not found
    """
    import base64
    from flask import Response
    
    es = ElasticsearchService()
    
    try:
        result = es.get('scan_results', scan_id)
        if result:
            doc = result['_source']
            
            # Check if user owns this scan or is admin
            if doc.get('user_id') != g.current_user.id and not g.current_user.has_role('Admin'):
                return jsonify({'error': 'Access denied'}), 403
            
            scan_result = doc.get('result', {})
            screenshot_b64 = scan_result.get('screenshot')
            
            if screenshot_b64:
                screenshot_bytes = base64.b64decode(screenshot_b64)
                return Response(
                    screenshot_bytes,
                    mimetype='image/png',
                    headers={
                        'Content-Disposition': f'inline; filename="urlscan-{scan_id}.png"'
                    }
                )
    except Exception as e:
        logger.error(f"[URLScan] Error getting screenshot: {e}")
    
    return jsonify({'error': 'Screenshot not found'}), 404
