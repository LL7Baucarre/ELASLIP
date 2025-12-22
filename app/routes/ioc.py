"""IOC API Routes."""

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.ioc_service import IOCService
from app.utils.pattern_generator import PatternGenerator

ioc_bp = Blueprint('ioc', __name__, url_prefix=None)


@ioc_bp.route('/', methods=['POST'], strict_slashes=False)
@login_or_api_key_required
def create_ioc():
    """
    Create a new IOC.
    ---
    tags:
      - IOCs
    summary: Create a new Indicator of Compromise
    parameters:
      - in: header
        name: Authorization
        description: Bearer token or API key
        required: false
        schema:
          type: string
    requestBody:
      description: IOC data to create
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - type
              - value
            properties:
              type:
                type: string
                enum: [md5, sha1, sha256, ipv4, domain, email, url, asn]
                description: IOC type
              value:
                type: string
                description: IOC value
              labels:
                type: array
                items:
                  type: string
                description: Labels for categorization
              source:
                type: string
                description: Source of the IOC
              name:
                type: string
                description: Optional indicator name
              description:
                type: string
                description: Optional description
              threat_level:
                type: string
                enum: [unknown, low, medium, high, critical]
                description: Threat level assessment
    responses:
      201:
        description: IOC created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            is_new:
              type: boolean
            ioc:
              type: object
      400:
        description: Invalid input
        schema:
          type: object
          properties:
            error:
              type: string
    """
    print(f"DEBUG: Received request. Headers: {dict(request.headers)}")
    print(f"DEBUG: Content-Type: {request.content_type}")
    print(f"DEBUG: Data: {request.data}")
    
    data = request.get_json()
    
    print(f"DEBUG: Parsed JSON: {data}")
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    ioc_type = data.get('type')
    value = data.get('value')
    
    if not ioc_type or not value:
        return jsonify({'error': 'type and value are required'}), 400
    
    # Normalize type
    ioc_type = ioc_type.lower()
    
    if ioc_type not in PatternGenerator.SUPPORTED_TYPES:
        return jsonify({
            'error': f'Unsupported IOC type: {ioc_type}',
            'supported_types': PatternGenerator.SUPPORTED_TYPES
        }), 400
    
    # Validate value
    if not PatternGenerator.validate_value(ioc_type, value):
        return jsonify({'error': f'Invalid {ioc_type} value: {value}'}), 400
    
    # Prepare source
    source = {
        'name': data.get('source', 'manual'),
        'metadata': {
            'user_id': g.current_user.id,
            'username': g.current_user.username,
            'threat_level': data.get('threat_level', 'unknown')
        }
    }
    
    try:
        service = IOCService()
        ioc, is_new = service.create(
            ioc_type=ioc_type,
            value=value,
            labels=data.get('labels', []),
            source=source,
            name=data.get('name'),
            description=data.get('description'),
            threat_level=data.get('threat_level', 'unknown')
        )
        
        status_code = 201 if is_new else 200
        message = 'IOC created successfully' if is_new else 'IOC already exists, source added'
        
        return jsonify({
            'message': message,
            'is_new': is_new,
            'ioc': ioc
        }), status_code
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@ioc_bp.route('', methods=['GET'])
@login_or_api_key_required
def list_iocs():
    """
    List IOCs with pagination and filters.
    ---
    tags:
      - IOCs
    summary: List all IOCs
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
        name: type
        schema:
          type: string
          enum: [md5, sha1, sha256, ipv4, domain, email, url, asn]
        description: Filter by IOC type
      - in: query
        name: labels
        schema:
          type: string
        description: Comma-separated labels to filter
      - in: query
        name: source
        schema:
          type: string
        description: Filter by source name
    responses:
      200:
        description: List of IOCs
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
            per_page:
              type: integer
    """
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    ioc_type = request.args.get('type')
    labels = request.args.get('labels')
    source = request.args.get('source')
    
    if labels:
        labels = [l.strip() for l in labels.split(',')]
    
    service = IOCService()
    result = service.list(
        page=page,
        per_page=per_page,
        ioc_type=ioc_type,
        labels=labels,
        source=source
    )
    
    return jsonify(result)


@ioc_bp.route('/stats', methods=['GET'])
@login_or_api_key_required
def get_stats():
    """Get IOC statistics."""
    service = IOCService()
    stats = service.get_stats()
    return jsonify(stats)


@ioc_bp.route('/types', methods=['GET'])
def get_supported_types():
    """Get supported IOC types."""
    return jsonify({
        'types': PatternGenerator.SUPPORTED_TYPES,
        'patterns': PatternGenerator.PATTERN_TEMPLATES
    })


@ioc_bp.route('/<ioc_id>', methods=['GET'])
@login_or_api_key_required
def get_ioc(ioc_id):
    """Get a single IOC by ID."""
    service = IOCService()
    ioc = service.get(ioc_id)
    
    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404
    
    return jsonify(ioc)


@ioc_bp.route('/<ioc_id>', methods=['PUT', 'PATCH'])
@login_or_api_key_required
def update_ioc(ioc_id):
    """
    Update an IOC.
    ---
    tags:
      - IOCs
    summary: Update IOC
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: IOC ID
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              name:
                type: string
                description: IOC name
              description:
                type: string
                description: IOC description
              labels:
                type: array
                items:
                  type: string
                description: IOC labels/tags
    responses:
      200:
        description: IOC updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
            ioc:
              type: object
      400:
        description: Invalid request
      404:
        description: IOC not found
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    service = IOCService()
    ioc = service.update(ioc_id, data)
    
    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404
    
    return jsonify({
        'message': 'IOC updated successfully',
        'ioc': ioc
    })


@ioc_bp.route('/<ioc_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_ioc(ioc_id):
    """
    Delete an IOC.
    ---
    tags:
      - IOCs
    summary: Delete IOC
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: IOC ID to delete
    responses:
      200:
        description: IOC deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      404:
        description: IOC not found
    """
    service = IOCService()
    success = service.delete(ioc_id)
    
    if not success:
        return jsonify({'error': 'IOC not found'}), 404
    
    return jsonify({'message': 'IOC deleted successfully'})


@ioc_bp.route('/<ioc_id>/sources', methods=['GET'])
@login_or_api_key_required
def get_ioc_sources(ioc_id):
    """Get all sources for an IOC."""
    service = IOCService()
    ioc = service.get(ioc_id)
    
    if not ioc:
        return jsonify({'error': 'IOC not found'}), 404
    
    sources = ioc.get('sources', [])
    return jsonify({
        'ioc_id': ioc_id,
        'sources': sources,
        'total': len(sources)
    })


@ioc_bp.route('/validate', methods=['POST'])
def validate_ioc():
    """
    Validate an IOC value without creating it.
    
    Expected JSON body:
    {
        "type": "ioc type (optional, will auto-detect)",
        "value": "the value to validate"
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    value = data.get('value')
    if not value:
        return jsonify({'error': 'value is required'}), 400
    
    ioc_type = data.get('type')
    
    if ioc_type:
        ioc_type = ioc_type.lower()
        is_valid = PatternGenerator.validate_value(ioc_type, value)
    else:
        # Auto-detect type
        ioc_type = PatternGenerator.detect_type(value)
        is_valid = ioc_type is not None
    
    result = {
        'value': value,
        'valid': is_valid,
        'detected_type': ioc_type
    }
    
    if is_valid:
        try:
            result['pattern'] = PatternGenerator.generate_pattern(ioc_type, value)
        except ValueError:
            result['valid'] = False
    
    return jsonify(result)


@ioc_bp.route('/stix', methods=['POST'])
@login_or_api_key_required
def create_from_stix():
    """
    Create an IOC from raw STIX 2.1 JSON.
    
    Expected JSON body: A valid STIX 2.1 Indicator object.
    Required fields:
    - type: "indicator"
    - pattern: STIX pattern
    - pattern_type: "stix"
    - valid_from: ISO timestamp
    """
    import re
    import uuid
    from datetime import datetime
    
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Validate STIX indicator
    if data.get('type') != 'indicator':
        return jsonify({'error': 'Object type must be "indicator"'}), 400
    
    pattern = data.get('pattern')
    if not pattern:
        return jsonify({'error': 'Missing required field: pattern'}), 400
    
    pattern_type = data.get('pattern_type', 'stix')
    if pattern_type != 'stix':
        return jsonify({'error': 'Only pattern_type "stix" is supported'}), 400
    
    # Extract IOC type and value from pattern
    ioc_type = None
    value = None
    
    # Pattern extractors
    pattern_extractors = {
        'md5': re.compile(r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", re.IGNORECASE),
        'sha1': re.compile(r"\[file:hashes\.SHA1\s*=\s*'([^']+)'\]", re.IGNORECASE),
        'sha256': re.compile(r"\[file:hashes\.SHA256\s*=\s*'([^']+)'\]", re.IGNORECASE),
        'ipv4': re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
        'domain': re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
        'email': re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]"),
        'url': re.compile(r"\[url:value\s*=\s*'([^']+)'\]"),
        'asn': re.compile(r"\[autonomous-system:number\s*=\s*(\d+)\]")
    }
    
    for t, regex in pattern_extractors.items():
        match = regex.search(pattern)
        if match:
            ioc_type = t
            value = match.group(1)
            # For ASN, prepend AS prefix if not present
            if t == 'asn' and not value.upper().startswith('AS'):
                value = f'AS{value}'
            break
    
    if not ioc_type or not value:
        return jsonify({
            'error': 'Could not extract IOC type and value from pattern',
            'pattern': pattern
        }), 400
    
    # Prepare source
    source = {
        'name': 'stix-import',
        'metadata': {
            'user_id': g.current_user.id,
            'username': g.current_user.username,
            'original_id': data.get('id'),
            'original_created': data.get('created'),
            'original_modified': data.get('modified')
        }
    }
    
    try:
        service = IOCService()
        ioc, is_new = service.create(
            ioc_type=ioc_type,
            value=value,
            labels=data.get('labels', []) or data.get('indicator_types', []),
            source=source,
            name=data.get('name'),
            description=data.get('description')
        )
        
        status_code = 201 if is_new else 200
        message = 'STIX indicator imported successfully' if is_new else 'Indicator already exists, source added'
        
        return jsonify({
            'message': message,
            'is_new': is_new,
            'ioc': ioc
        }), status_code
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
