"""Audit Log Routes for activity timeline."""

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.audit_service import AuditService

audit_bp = Blueprint('audit', __name__, url_prefix='/api/audit')


@audit_bp.route('logs', methods=['GET'])
@login_or_api_key_required
def list_logs():
    """
    List audit logs with optional filters.
    ---
    tags:
      - Audit & Timeline
    summary: Get audit logs
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
          default: 50
        description: Items per page
      - in: query
        name: action
        schema:
          type: string
        description: Filter by action type
      - in: query
        name: entity_type
        schema:
          type: string
        description: Filter by entity type
      - in: query
        name: user_id
        schema:
          type: string
        description: Filter by user ID
      - in: query
        name: from_date
        schema:
          type: string
          format: date-time
        description: Filter from date
      - in: query
        name: to_date
        schema:
          type: string
          format: date-time
        description: Filter to date
    responses:
      200:
        description: Audit logs retrieved
    """
    service = AuditService()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    filters = {}
    if request.args.get('action'):
        filters['action'] = request.args.get('action')
    if request.args.get('entity_type'):
        filters['entity_type'] = request.args.get('entity_type')
    if request.args.get('user_id'):
        filters['user_id'] = request.args.get('user_id')
    if request.args.get('from_date'):
        filters['from_date'] = request.args.get('from_date')
    if request.args.get('to_date'):
        filters['to_date'] = request.args.get('to_date')
    
    result = service.list(page=page, per_page=per_page, **filters)
    
    return jsonify(result), 200


@audit_bp.route('entity/<entity_type>/<entity_id>', methods=['GET'])
@login_or_api_key_required
def get_entity_history(entity_type, entity_id):
    """
    Get audit history for a specific entity.
    ---
    tags:
      - Audit & Timeline
    summary: Get entity history
    parameters:
      - in: path
        name: entity_type
        required: true
        schema:
          type: string
        description: Entity type (ioc, user, webhook, etc.)
      - in: path
        name: entity_id
        required: true
        schema:
          type: string
        description: Entity ID
      - in: query
        name: limit
        schema:
          type: integer
          default: 50
        description: Maximum number of logs to return
    responses:
      200:
        description: Entity history retrieved
    """
    service = AuditService()
    
    limit = request.args.get('limit', 50, type=int)
    
    logs = service.get_by_entity(entity_type, entity_id, limit=limit)
    
    return jsonify({
        'entity_type': entity_type,
        'entity_id': entity_id,
        'logs': logs,
        'count': len(logs)
    }), 200


@audit_bp.route('user/<user_id>/activity', methods=['GET'])
@login_or_api_key_required
def get_user_activity(user_id):
    """
    Get activity timeline for a specific user.
    ---
    tags:
      - Audit & Timeline
    summary: Get user activity
    parameters:
      - in: path
        name: user_id
        required: true
        schema:
          type: string
        description: User ID
      - in: query
        name: limit
        schema:
          type: integer
          default: 100
        description: Maximum number of activities to return
    responses:
      200:
        description: User activity retrieved
    """
    service = AuditService()
    
    limit = request.args.get('limit', 100, type=int)
    
    activities = service.get_user_activity(user_id, limit=limit)
    
    return jsonify({
        'user_id': user_id,
        'activities': activities,
        'count': len(activities)
    }), 200


@audit_bp.route('my-activity', methods=['GET'])
@login_or_api_key_required
def get_my_activity():
    """
    Get current user's activity timeline.
    ---
    tags:
      - Audit & Timeline
    summary: Get current user's activity
    parameters:
      - in: query
        name: limit
        schema:
          type: integer
          default: 100
        description: Maximum number of activities to return
    responses:
      200:
        description: User activity retrieved
    """
    service = AuditService()
    
    user_id = str(g.current_user.id)
    limit = request.args.get('limit', 100, type=int)
    
    activities = service.get_user_activity(user_id, limit=limit)
    
    return jsonify({
        'user_id': user_id,
        'activities': activities,
        'count': len(activities)
    }), 200


@audit_bp.route('stats', methods=['GET'])
@login_or_api_key_required
def get_stats():
    """
    Get audit statistics.
    ---
    tags:
      - Audit & Timeline
    summary: Get audit statistics
    parameters:
      - in: query
        name: days
        schema:
          type: integer
          default: 30
        description: Number of days to analyze
    responses:
      200:
        description: Audit statistics
    """
    service = AuditService()
    
    days = request.args.get('days', 30, type=int)
    
    stats = service.get_stats(days=days)
    
    return jsonify(stats), 200
