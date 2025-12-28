"""Audit Log Routes for activity timeline."""

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.services.audit_service import AuditService
from app.utils.request_helpers import get_pagination_params, build_filters_dict

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
    
    page, per_page = get_pagination_params(default_per_page=50)
    
    filters = build_filters_dict({
        'action': None,
        'entity_type': None,
        'user_id': None,
        'from_date': None,
        'to_date': None
    })
    
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


# Elasticsearch Statistics Route
from app.decorators import permission_required

@audit_bp.route('/elasticsearch/stats', methods=['GET'])
@login_or_api_key_required
@permission_required('admin.elasticsearch.stats', 'audit.view', require_all=False)
def get_elasticsearch_stats():
    """
    Get Elasticsearch cluster and index statistics.
    ---
    tags:
      - Elasticsearch Stats
    summary: Get Elasticsearch statistics
    responses:
      200:
        description: Elasticsearch statistics
    """
    from app.services.elasticsearch_service import ElasticsearchService
    
    es = ElasticsearchService()
    
    try:
        # Get cluster health
        health = es.client.cluster.health()
        
        # Get node count
        nodes = es.client.nodes.info(filter_path='nodes.*.name')
        node_count = len(nodes.get('nodes', {}))
        
        # Get indices stats
        indices_stats = es.client.indices.stats(expand_wildcards='all')
        indices_data = []
        total_docs = 0
        total_size = 0
        
        for index_name, index_info in indices_stats.get('indices', {}).items():
            # Skip system indices
            if index_name.startswith('.'):
                continue
                
            doc_count = index_info['primaries']['docs']['count']
            size_bytes = index_info['primaries']['store']['size_in_bytes']
            
            # Get index settings for shard info
            try:
                index_settings = es.client.indices.get_settings(index=index_name)
                num_shards = int(index_settings[index_name]['settings']['index']['number_of_shards'])
                num_replicas = int(index_settings[index_name]['settings']['index']['number_of_replicas'])
            except:
                num_shards = 1
                num_replicas = 0
            
            # Get index status
            try:
                index_health = es.client.cluster.health(index=index_name)
                status = index_health.get('status', 'unknown')
            except:
                status = 'unknown'
            
            indices_data.append({
                'name': index_name,
                'doc_count': doc_count,
                'size_bytes': size_bytes,
                'primary_shards': num_shards,
                'replica_shards': num_replicas,
                'status': status
            })
            
            total_docs += doc_count
            total_size += size_bytes
        
        return jsonify({
            'cluster_health': health.get('status', 'unknown'),
            'active_shards': health.get('active_shards', 0),
            'node_count': node_count,
            'indices_count': len(indices_data),
            'total_documents': total_docs,
            'total_size_bytes': total_size,
            'indices': indices_data
        }), 200
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'cluster_health': 'error',
            'active_shards': 0,
            'node_count': 0,
            'indices_count': 0,
            'total_documents': 0,
            'total_size_bytes': 0,
            'indices': []
        }), 200
