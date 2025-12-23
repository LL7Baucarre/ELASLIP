"""IOC Relations API Routes - Link related IOCs together."""

from flask import Blueprint, request, jsonify, g
from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from datetime import datetime
import uuid

ioc_relations_bp = Blueprint('ioc_relations', __name__, url_prefix=None)


@ioc_relations_bp.route('/ioc/<ioc_id>/relations', methods=['GET'])
@login_or_api_key_required
def get_ioc_relations(ioc_id):
    """
    Get all IOCs related to a specific IOC.
    ---
    tags:
      - IOC Relations
    summary: Get Related IOCs
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: IOC ID to get relations for
    responses:
      200:
        description: List of related IOCs
        schema:
          type: object
          properties:
            related_iocs:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  value:
                    type: string
                  type:
                    type: string
                  threat_level:
                    type: string
                  relation_type:
                    type: string
                    description: Type of relation (related, caused_by, used_by, etc.)
      404:
        description: IOC not found
    """
    es = ElasticsearchService()
    
    # Find relations where this IOC is the source or target
    relations = es.search('ioc_relations', {
        'query': {
            'bool': {
                'should': [
                    {'term': {'source_id': ioc_id}},
                    {'term': {'target_id': ioc_id}}
                ]
            }
        },
        'size': 100
    })
    
    related_iocs = []
    for rel in relations.get('hits', {}).get('hits', []):
        relation = rel['_source']
        # Get the other IOC ID
        other_id = relation['target_id'] if relation['source_id'] == ioc_id else relation['source_id']
        
        # Get the related IOC
        try:
            ioc = es.get('ioc', other_id)
            if ioc:
                ioc_data = ioc['_source']
                ioc_data['id'] = other_id
                ioc_data['relation_type'] = relation.get('relation_type', 'related')
                related_iocs.append(ioc_data)
        except:
            pass
    
    return jsonify({'related_iocs': related_iocs}), 200


@ioc_relations_bp.route('/ioc/<ioc_id>/relations', methods=['POST'])
@login_or_api_key_required
def create_ioc_relation(ioc_id):
    """
    Link an IOC to one or more other IOCs.
    ---
    tags:
      - IOC Relations
    summary: Create IOC Relation
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: Source IOC ID
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - related_ioc_ids
            properties:
              related_ioc_ids:
                type: array
                items:
                  type: string
                description: Array of target IOC IDs to link
              relation_type:
                type: string
                enum:
                  - related
                  - caused_by
                  - used_by
                  - implements
                  - variant_of
                default: related
                description: Type of relationship
    responses:
      201:
        description: Relations created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            relation_ids:
              type: array
              items:
                type: string
      400:
        description: Invalid request
      404:
        description: IOC not found
    """
    es = ElasticsearchService()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Support both singular (related_ioc_id) and plural (related_ioc_ids) formats
    related_ids = data.get('related_ioc_ids', [])
    
    # If singular format is used, convert to list
    if not related_ids and data.get('related_ioc_id'):
        related_ids = [data.get('related_ioc_id')]
    
    relation_type = data.get('relation_type', 'related')  # related, caused_by, used_by, etc.
    
    if not related_ids:
        return jsonify({'error': 'related_ioc_ids or related_ioc_id is required'}), 400
    
    if not isinstance(related_ids, list):
        return jsonify({'error': 'related_ioc_ids must be an array'}), 400
    
    # Verify source IOC exists
    source_ioc = es.get('ioc', ioc_id)
    if not source_ioc:
        return jsonify({'error': 'Source IOC not found'}), 404
    
    created_relations = []
    
    # Create bidirectional relations
    for target_id in related_ids:
        if target_id == ioc_id:
            continue  # Skip self-relations
        
        # Verify target IOC exists
        target_ioc = es.get('ioc', target_id)
        if not target_ioc:
            continue  # Skip non-existent IOCs
        
        # Check if relation already exists (avoid duplicates)
        existing = es.search('ioc_relations', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'relation_type': relation_type}},
                        {'bool': {
                            'should': [
                                {
                                    'bool': {
                                        'must': [
                                            {'term': {'source_id': ioc_id}},
                                            {'term': {'target_id': target_id}}
                                        ]
                                    }
                                },
                                {
                                    'bool': {
                                        'must': [
                                            {'term': {'source_id': target_id}},
                                            {'term': {'target_id': ioc_id}}
                                        ]
                                    }
                                }
                            ]
                        }}
                    ]
                }
            },
            'size': 1
        })
        
        if existing['hits']['total']['value'] > 0:
            continue  # Relation already exists
        
        # Create relation (bidirectional)
        relation_id = str(uuid.uuid4())
        relation = {
            'source_id': ioc_id,
            'target_id': target_id,
            'relation_type': relation_type,
            'created_by': g.current_user.id,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'bidirectional': True
        }
        
        es.index('ioc_relations', relation_id, relation)
        created_relations.append(relation_id)
    
    return jsonify({
        'message': f'Created {len(created_relations)} relation(s)',
        'relation_ids': created_relations
    }), 201


@ioc_relations_bp.route('/ioc/<ioc_id>/relations/<relation_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_ioc_relation(ioc_id, relation_id):
    """
    Delete a relation between IOCs.
    ---
    tags:
      - IOC Relations
    summary: Delete IOC Relation
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: IOC ID
      - in: path
        name: relation_id
        schema:
          type: string
        required: true
        description: Relation ID to delete
    responses:
      200:
        description: Relation deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      403:
        description: Relation does not involve the specified IOC
      404:
        description: Relation not found
    """
    es = ElasticsearchService()
    
    # Verify the relation exists and involves this IOC
    relation = es.get('ioc_relations', relation_id)
    if not relation:
        return jsonify({'error': 'Relation not found'}), 404
    
    rel_data = relation['_source']
    if rel_data['source_id'] != ioc_id and rel_data['target_id'] != ioc_id:
        return jsonify({'error': 'This relation does not involve the specified IOC'}), 403
    
    es.delete('ioc_relations', relation_id)
    
    return jsonify({'message': 'Relation deleted successfully'}), 200


@ioc_relations_bp.route('/search/by-relation', methods=['POST'])
@login_or_api_key_required
def search_by_relation():
    """Search IOCs by following relations (graph traversal)."""
    es = ElasticsearchService()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    start_ioc_id = data.get('start_ioc_id')
    depth = data.get('depth', 1)  # How many hops to follow
    relation_type = data.get('relation_type')  # Filter by relation type (optional)
    
    if not start_ioc_id:
        return jsonify({'error': 'start_ioc_id is required'}), 400
    
    # Verify start IOC exists
    start_ioc = es.get('ioc', start_ioc_id)
    if not start_ioc:
        return jsonify({'error': 'Start IOC not found'}), 404
    
    visited = set()
    to_visit = [start_ioc_id]
    all_iocs = {}
    
    for current_depth in range(depth):
        next_visit = []
        
        for ioc_id in to_visit:
            if ioc_id in visited:
                continue
            
            visited.add(ioc_id)
            
            # Get this IOC
            try:
                ioc = es.get('ioc', ioc_id)
                if ioc:
                    ioc_data = ioc['_source']
                    ioc_data['id'] = ioc_id
                    ioc_data['depth'] = current_depth
                    all_iocs[ioc_id] = ioc_data
            except:
                pass
            
            # Find related IOCs
            query = {
                'query': {
                    'bool': {
                        'should': [
                            {'term': {'source_id': ioc_id}},
                            {'term': {'target_id': ioc_id}}
                        ]
                    }
                },
                'size': 100
            }
            
            if relation_type:
                query['query']['bool']['must'] = {'term': {'relation_type': relation_type}}
            
            relations = es.search('ioc_relations', query)
            
            for rel in relations.get('hits', {}).get('hits', []):
                relation = rel['_source']
                other_id = relation['target_id'] if relation['source_id'] == ioc_id else relation['source_id']
                
                if other_id not in visited:
                    next_visit.append(other_id)
        
        to_visit = next_visit
    
    return jsonify({
        'start_ioc_id': start_ioc_id,
        'depth': depth,
        'total_found': len(all_iocs),
        'iocs': list(all_iocs.values())
    }), 200
