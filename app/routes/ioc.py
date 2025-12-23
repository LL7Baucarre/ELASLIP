"""IOC API Routes."""

import re
from datetime import datetime
from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.ioc_service import IOCService
from app.services.audit_service import AuditService
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
                enum: [md5, sha1, sha256, ipv4, ipv6, domain, email, url, asn, file-path, process-name, registry-key, windows-registry-key, mutex, certificate-serial]
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
              confidence:
                type: string
                enum: [low, medium, high, very-high]
                description: Confidence level in the indicator
              tlp:
                type: string
                enum: [white, green, amber, red]
                description: Traffic Light Protocol level
              campaigns:
                type: array
                items:
                  type: string
                description: Related campaigns or operations
              valid_from:
                type: string
                format: date-time
                description: Validity start date (ISO 8601 format)
              valid_until:
                type: string
                format: date-time
                description: Validity end date (ISO 8601 format)
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
            threat_level=data.get('threat_level', 'unknown'),
            confidence=data.get('confidence'),
            tlp=data.get('tlp'),
            campaigns=data.get('campaigns', []),
            valid_from=data.get('valid_from'),
            valid_until=data.get('valid_until'),
            user_id=g.current_user.id,
            username=g.current_user.username
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


# ============================================================
# VERSIONING ENDPOINTS
# ============================================================

@ioc_bp.route('/<ioc_id>/versions', methods=['GET'])
@login_or_api_key_required
def get_versions(ioc_id):
    """
    Get version history for an IOC.
    ---
    tags:
      - IOC Versioning
    summary: Get version history of an IOC
    parameters:
      - in: path
        name: ioc_id
        required: true
        schema:
          type: string
        description: IOC ID
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
        description: Items per page
    responses:
      200:
        description: Version history retrieved
    """
    service = IOCService()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    versions = service.get_versions(ioc_id, page=page, per_page=per_page)
    
    # Get current IOC to include current_version
    current_ioc = service.get(ioc_id)
    current_version = current_ioc.get('current_version', 1) if current_ioc else 1
    
    # Transform response to match frontend expectations
    response = {
        'versions': versions.get('items', []),
        'total': versions.get('total', 0),
        'current_version': current_version,
        'page': versions.get('page', page),
        'per_page': versions.get('per_page', per_page)
    }
    
    return jsonify(response), 200


@ioc_bp.route('/<ioc_id>/versions/<int:version>/restore', methods=['POST'])
@login_or_api_key_required
def restore_version(ioc_id, version):
    """
    Restore an IOC to a previous version.
    ---
    tags:
      - IOC Versioning
    summary: Restore IOC to a previous version
    parameters:
      - in: path
        name: ioc_id
        required: true
        schema:
          type: string
        description: IOC ID
      - in: path
        name: version
        required: true
        schema:
          type: integer
        description: Version number to restore
    responses:
      200:
        description: IOC restored successfully
      404:
        description: Version not found
    """
    service = IOCService()
    
    user_id = str(g.current_user.id)
    username = g.current_user.username
    
    result = service.restore_version(ioc_id, version, user_id=user_id, username=username)
    
    if not result:
        return jsonify({'error': 'Version not found'}), 404
    
    return jsonify({
        'message': f'IOC restored to version {version}',
        'ioc': result
    }), 200


# ============================================================
# BULK OPERATIONS ENDPOINTS
# ============================================================

@ioc_bp.route('/bulk/update', methods=['POST'])
@login_or_api_key_required
def bulk_update():
    """
    Update multiple IOCs at once.
    ---
    tags:
      - Bulk Operations
    summary: Bulk update IOCs
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - ioc_ids
              - updates
            properties:
              ioc_ids:
                type: array
                items:
                  type: string
                description: List of IOC IDs to update
              updates:
                type: object
                properties:
                  labels:
                    type: array
                    items:
                      type: string
                  threat_level:
                    type: string
                    enum: [unknown, low, medium, high, critical]
                  confidence:
                    type: string
                    enum: [low, medium, high, very-high]
                  tlp:
                    type: string
                    enum: [white, green, amber, red]
                  status:
                    type: string
                    enum: [active, archived, expired]
    responses:
      200:
        description: Bulk update completed
    """
    data = request.get_json()
    
    if not data or 'ioc_ids' not in data or 'updates' not in data:
        return jsonify({'error': 'ioc_ids and updates are required'}), 400
    
    ioc_ids = data['ioc_ids']
    updates = data['updates']
    
    if not isinstance(ioc_ids, list) or len(ioc_ids) == 0:
        return jsonify({'error': 'ioc_ids must be a non-empty array'}), 400
    
    service = IOCService()
    
    user_id = str(g.current_user.id)
    username = g.current_user.username
    
    result = service.bulk_update(ioc_ids, updates, user_id=user_id, username=username)
    
    # Log bulk operation to audit trail
    try:
        audit = AuditService()
        audit.log(
            action='bulk_update',
            entity_type='ioc',
            entity_id='bulk',
            entity_name=f'Bulk update {len(ioc_ids)} IOCs',
            changes=updates,
            user_id=user_id,
            username=username
        )
    except Exception:
        pass
    
    return jsonify(result), 200


@ioc_bp.route('/bulk/delete', methods=['POST'])
@login_or_api_key_required
def bulk_delete():
    """
    Delete multiple IOCs at once.
    ---
    tags:
      - Bulk Operations
    summary: Bulk delete IOCs
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - ioc_ids
            properties:
              ioc_ids:
                type: array
                items:
                  type: string
                description: List of IOC IDs to delete
    responses:
      200:
        description: Bulk delete completed
    """
    data = request.get_json()
    
    if not data or 'ioc_ids' not in data:
        return jsonify({'error': 'ioc_ids is required'}), 400
    
    ioc_ids = data['ioc_ids']
    
    if not isinstance(ioc_ids, list) or len(ioc_ids) == 0:
        return jsonify({'error': 'ioc_ids must be a non-empty array'}), 400
    
    service = IOCService()
    
    user_id = str(g.current_user.id)
    username = g.current_user.username
    
    result = service.bulk_delete(ioc_ids, user_id=user_id, username=username)
    
    # Log bulk operation to audit trail
    try:
        audit = AuditService()
        audit.log(
            action='bulk_delete',
            entity_type='ioc',
            entity_id='bulk',
            entity_name=f'Bulk delete {len(ioc_ids)} IOCs',
            changes={'deleted': True},
            user_id=user_id,
            username=username
        )
    except Exception:
        pass
    
    return jsonify(result), 200


@ioc_bp.route('/bulk/export', methods=['POST'])
@login_or_api_key_required
def bulk_export():
    """
    Export multiple IOCs based on filters.
    ---
    tags:
      - Bulk Operations
    summary: Bulk export IOCs
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              ioc_ids:
                type: array
                items:
                  type: string
                description: Specific IOC IDs to export (optional)
              filters:
                type: object
                properties:
                  type:
                    type: string
                  labels:
                    type: array
                    items:
                      type: string
                  threat_level:
                    type: string
                  tlp:
                    type: string
                  status:
                    type: string
              format:
                type: string
                enum: [json, stix, csv]
                default: json
    responses:
      200:
        description: Export data
    """
    data = request.get_json() or {}
    
    service = IOCService()
    
    ioc_ids = data.get('ioc_ids')
    filters = data.get('filters', {})
    export_format = data.get('format', 'json')
    
    iocs = service.bulk_export(ioc_ids=ioc_ids, filters=filters)
    
    # Log bulk operation to audit trail
    try:
        audit = AuditService()
        user_id = str(g.current_user.id) if hasattr(g, 'current_user') else 'system'
        username = g.current_user.username if hasattr(g, 'current_user') else 'system'
        audit.log(
            action='bulk_export',
            entity_type='ioc',
            entity_id='bulk',
            entity_name=f'Bulk export {len(iocs)} IOCs as {export_format}',
            changes={'format': export_format, 'count': len(iocs)},
            user_id=user_id,
            username=username
        )
    except Exception:
        pass
    
    if export_format == 'csv':
        # Generate CSV
        import csv
        from io import StringIO
        
        output = StringIO()
        if iocs:
            fieldnames = ['id', 'type', 'value', 'threat_level', 'confidence', 'tlp', 'risk_score', 'status', 'created']
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for ioc in iocs:
                writer.writerow(ioc)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=iocs_export.csv'}
        )
    
    elif export_format == 'stix':
        # Convert to STIX bundle
        from datetime import datetime
        
        stix_objects = []
        for ioc in iocs:
            stix_obj = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{ioc['id']}",
                'created': ioc.get('created', datetime.utcnow().isoformat()),
                'modified': ioc.get('modified', datetime.utcnow().isoformat()),
                'indicator_types': ioc.get('labels', ['unknown']),
                'pattern': ioc.get('pattern', f"[file:hashes.'{ioc['type']}' = '{ioc['value']}']"),
                'pattern_type': 'stix',
                'valid_from': ioc.get('valid_from', ioc.get('created'))
            }
            if ioc.get('name'):
                stix_obj['name'] = ioc['name']
            if ioc.get('description'):
                stix_obj['description'] = ioc['description']
            stix_objects.append(stix_obj)
        
        bundle = {
            'type': 'bundle',
            'id': f"bundle--{str(__import__('uuid').uuid4())}",
            'objects': stix_objects
        }
        
        return jsonify(bundle), 200
    
    # Default: JSON
    return jsonify({'iocs': iocs, 'count': len(iocs)}), 200


# ============================================================
# EXPIRATION ENDPOINTS
# ============================================================

@ioc_bp.route('/expired', methods=['GET'])
@login_or_api_key_required
def get_expired():
    """
    Get all expired IOCs.
    ---
    tags:
      - IOC Expiration
    summary: Get expired IOCs
    responses:
      200:
        description: List of expired IOCs
    """
    service = IOCService()
    
    expired = service.get_expired_iocs()
    
    return jsonify({
        'expired': expired,
        'count': len(expired)
    }), 200


@ioc_bp.route('/expiring-soon', methods=['GET'])
@login_or_api_key_required
def get_expiring_soon():
    """
    Get IOCs expiring soon.
    ---
    tags:
      - IOC Expiration
    summary: Get IOCs expiring within specified days
    parameters:
      - in: query
        name: days
        schema:
          type: integer
          default: 7
        description: Number of days to check
    responses:
      200:
        description: List of expiring IOCs
    """
    service = IOCService()
    
    days = request.args.get('days', 7, type=int)
    expiring = service.get_expiring_soon(days=days)
    
    return jsonify({
        'expiring_soon': expiring,
        'count': len(expiring),
        'days': days
    }), 200


@ioc_bp.route('/archive-expired', methods=['POST'])
@login_or_api_key_required
def archive_expired():
    """
    Archive all expired IOCs.
    ---
    tags:
      - IOC Expiration
    summary: Archive expired IOCs
    responses:
      200:
        description: Archive operation completed
    """
    service = IOCService()
    
    result = service.archive_expired_iocs()
    
    return jsonify(result), 200

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
        description: Filter by IOC type
      - in: query
        name: labels
        schema:
          type: string
        description: Comma-separated labels to filter
      - in: query
        name: tlp
        schema:
          type: string
          enum: [white, green, amber, red]
        description: Filter by TLP level
      - in: query
        name: threat_level
        schema:
          type: string
          enum: [unknown, low, medium, high, critical]
        description: Filter by threat level
      - in: query
        name: confidence
        schema:
          type: string
          enum: [low, medium, high, very-high]
        description: Filter by confidence level
      - in: query
        name: campaigns
        schema:
          type: string
        description: Filter by campaigns
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
    tlp = request.args.get('tlp')
    threat_level = request.args.get('threat_level')
    confidence = request.args.get('confidence')
    campaigns = request.args.get('campaigns')
    
    if labels:
        labels = [l.strip() for l in labels.split(',')]
    
    service = IOCService()
    result = service.list(
        page=page,
        per_page=per_page,
        ioc_type=ioc_type,
        labels=labels,
        tlp=tlp,
        threat_level=threat_level,
        confidence=confidence,
        campaigns=campaigns
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
    
    # Return STIX 2.1 pure format
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
              threat_level:
                type: string
                enum: [unknown, low, medium, high, critical]
                description: Threat level
              confidence:
                type: string
                enum: [low, medium, high, very-high]
                description: Confidence level
              tlp:
                type: string
                enum: [white, green, amber, red]
                description: Traffic Light Protocol level
              campaigns:
                type: array
                items:
                  type: string
                description: Related campaigns
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
    
    user_id = str(g.current_user.id)
    username = g.current_user.username
    
    ioc = service.update(ioc_id, data, user_id=user_id, username=username)
    
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


# ============================================================
# ENRICHMENT ENDPOINT (STIX 2.1 COMPLIANT)
# ============================================================

@ioc_bp.route('/<ioc_id>/enrich', methods=['POST'])
@login_or_api_key_required
def enrich_ioc(ioc_id):
    """
    Enrich an IOC and return raw API results for user selection (STIX 2.1 compliant).
    
    User can then select which fields to add to x_enrichment via separate endpoint.
    
    Expected JSON body:
    {
        "api_ids": ["optional", "list", "of", "api", "ids"]  # If omitted, uses all enabled APIs
    }
    
    Response: Raw API results formatted for field selection in template
    """
    import logging
    logger = logging.getLogger(__name__)
    
    from app.services.enrichment_service import EnrichmentService
    from app.services.ioc_service import IOCService
    
    data = request.get_json() or {}
    
    logger.info(f'[Enrich IOC] Request for IOC {ioc_id}, user: {g.current_user.id}')
    
    # Get IOC from service
    ioc_service = IOCService()
    ioc = ioc_service.get(ioc_id)
    
    if not ioc:
        return jsonify({'error': f'IOC {ioc_id} not found'}), 404
    
    # Extract value from x_metadata.ioc_value or pattern
    value = None
    ioc_type = None
    
    if 'x_metadata' in ioc:
        value = ioc['x_metadata'].get('ioc_value')
        ioc_type = ioc['x_metadata'].get('ioc_type')
    
    # Fallback: extract from pattern
    if not value and 'pattern' in ioc:
        pattern = ioc['pattern']
        # Try to extract value from STIX pattern
        pattern_extractors = {
            'ipv4': re.compile(r"\[ipv4-addr:value = '([^']+)'\]"),
            'ipv6': re.compile(r"\[ipv6-addr:value = '([^']+)'\]"),
            'domain': re.compile(r"\[domain-name:value = '([^']+)'\]"),
            'url': re.compile(r"\[url:value = '([^']+)'\]"),
            'email': re.compile(r"\[email-addr:value = '([^']+)'\]"),
            'hash': re.compile(r"\[file:hashes\.'[A-Z0-9]+' = '([^']+)'\]"),
            'md5': re.compile(r"\[file:hashes\.'MD5' = '([^']+)'\]"),
            'sha1': re.compile(r"\[file:hashes\.'SHA-1' = '([^']+)'\]"),
            'sha256': re.compile(r"\[file:hashes\.'SHA-256' = '([^']+)'\]"),
            'asn': re.compile(r"\[autonomous-system:value = '(AS?\d+)'\]"),
            'file': re.compile(r"\[file:name = '([^']+)'\]")
        }
        
        for t, regex in pattern_extractors.items():
            match = regex.search(pattern)
            if match:
                ioc_type = t
                value = match.group(1)
                break
    
    if not value:
        return jsonify({'error': 'Could not extract IOC value from pattern or x_metadata'}), 400
    
    logger.info(f'[Enrich IOC] Extracted value: {value}, type: {ioc_type}')
    
    # Enrich using external APIs
    enrichment_service = EnrichmentService()
    
    try:
        api_ids = data.get('api_ids', [])
        
        if api_ids:
            logger.info(f'[Enrich IOC] Enriching with specific APIs: {api_ids}')
            results = enrichment_service.enrich_value_with_apis(
                value=value,
                ioc_type=ioc_type,
                user_id=str(g.current_user.id),
                api_ids=api_ids
            )
        else:
            logger.info(f'[Enrich IOC] Enriching with all enabled APIs')
            results = enrichment_service.enrich_value(
                value=value,
                ioc_type=ioc_type,
                user_id=str(g.current_user.id)
            )
        
        logger.info(f'[Enrich IOC] Enrichment completed with {len(results)} results')
        
        # Return results in template-friendly format (NOT storing yet)
        return jsonify({
            'value': value,
            'type': ioc_type,
            'results': results  # User selects fields from these results
        }), 200
    
    except Exception as e:
        logger.error(f'[Enrich IOC] Enrichment error: {str(e)}', exc_info=True)
        return jsonify({'error': f'Enrichment failed: {str(e)}'}), 400


@ioc_bp.route('/<ioc_id>/store-enrichment', methods=['POST'])
@login_or_api_key_required
def store_enrichment(ioc_id):
    """
    Store selected enrichment fields into IOC's x_enrichment object.
    
    Expected JSON body:
    {
        "api_name": "API name",
        "api_id": "api_id",
        "selected_fields": {
            "field1": "value1",
            "field2": "value2",
            ...
        }
    }
    
    Response: Updated STIX 2.1 indicator with x_enrichment
    """
    import logging
    logger = logging.getLogger(__name__)
    
    from app.services.ioc_service import IOCService
    
    data = request.get_json()
    
    if not data or 'selected_fields' not in data:
        return jsonify({'error': 'selected_fields is required'}), 400
    
    api_name = data.get('api_name', 'Unknown API')
    api_id = data.get('api_id', '')
    selected_fields = data['selected_fields']
    
    logger.info(f'[Store Enrichment] Storing fields for IOC {ioc_id} from {api_name}')
    
    ioc_service = IOCService()
    ioc = ioc_service.get(ioc_id)
    
    if not ioc:
        return jsonify({'error': f'IOC {ioc_id} not found'}), 404
    
    # Create or update x_enrichment
    x_enrichment = ioc.get('x_enrichment', {})
    if not isinstance(x_enrichment, dict):
        x_enrichment = {}
    
    # Ensure api_results array exists
    if 'api_results' not in x_enrichment:
        x_enrichment['api_results'] = []
    
    # Create result object with selected fields
    result = {
        'api_name': api_name,
        'api_id': api_id,
        'enriched_at': datetime.utcnow().isoformat() + 'Z',
        'enriched_by': g.current_user.username
    }
    result.update(selected_fields)
    
    # Add or merge result
    if len(x_enrichment['api_results']) > 0:
        # Find existing result from same API and merge
        found = False
        for stored_result in x_enrichment['api_results']:
            if stored_result.get('api_id') == api_id:
                stored_result.update(result)
                found = True
                break
        
        if not found:
            x_enrichment['api_results'].append(result)
    else:
        x_enrichment['api_results'].append(result)
    
    # Update IOC
    update_data = {'x_enrichment': x_enrichment}
    
    updated_ioc = ioc_service.update(
        ioc_id,
        update_data,
        user_id=str(g.current_user.id),
        username=g.current_user.username
    )
    
    logger.info(f'[Store Enrichment] Stored enrichment from {api_name} for IOC {ioc_id}')
    
    return jsonify({
        'message': f'Enrichment from {api_name} stored successfully',
        'ioc': updated_ioc
    }), 200

