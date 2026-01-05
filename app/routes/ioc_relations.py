"""IOC Relations API Routes - STIX 2.1 Relationship Objects (SROs)."""

from flask import Blueprint, request, jsonify, g
from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.services.ioc_service import IOCService
from app.models.stix_schema import STIXRelationship, STIX_RELATIONSHIP_TYPES
from datetime import datetime
import uuid

ioc_relations_bp = Blueprint('ioc_relations', __name__, url_prefix=None)


@ioc_relations_bp.route('/ioc/<ioc_id>/relations', methods=['GET'])
@login_or_api_key_required
def get_ioc_relations(ioc_id):
    """
    Get all STIX Relationships for a specific IOC.
    ---
    tags:
      - IOC Relations
    summary: Get Related IOCs (STIX 2.1)
    parameters:
      - in: path
        name: ioc_id
        schema:
          type: string
        required: true
        description: IOC ID (without indicator-- prefix) to get relations for
    responses:
      200:
        description: List of related IOCs with STIX relationship metadata
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
                  relationship_type:
                    type: string
                    description: STIX 2.1 relationship type (indicates, uses, related-to, etc.)
                  relationship_id:
                    type: string
                    description: STIX relationship ID (relationship--uuid)
      404:
        description: IOC not found
    """
    es = ElasticsearchService()
    ioc_service = IOCService()
    
    # Build source_ref from ioc_id (add indicator-- prefix if not present)
    if ioc_id.startswith('indicator--'):
        source_ref = ioc_id
    else:
        source_ref = f"indicator--{ioc_id}"
    
    # Find STIX relationships where this IOC is the source or target
    relations = es.search('stix_relationships', {
        'query': {
            'bool': {
                'should': [
                    {'term': {'source_ref': source_ref}},
                    {'term': {'target_ref': source_ref}}
                ],
                'minimum_should_match': 1
            }
        },
        'size': 100
    })
    
    related_iocs = []
    for rel in relations.get('hits', {}).get('hits', []):
        relationship = rel['_source']
        
        # Get the other IOC's ref
        if relationship['source_ref'] == source_ref:
            other_ref = relationship['target_ref']
        else:
            other_ref = relationship['source_ref']
        
        # Get the related IOC using IOCService (use full indicator--uuid ID)
        try:
            ioc_data = ioc_service.get(other_ref)
            if ioc_data:
                ioc_data['relationship_type'] = relationship.get('relationship_type', 'related-to')
                ioc_data['relationship_id'] = relationship.get('id', rel['_id'])
                related_iocs.append(ioc_data)
        except Exception:
            pass
    
    return jsonify({'related_iocs': related_iocs}), 200


@ioc_relations_bp.route('/ioc/<ioc_id>/relations', methods=['POST'])
@login_or_api_key_required
def create_ioc_relation(ioc_id):
    """
    Create a STIX 2.1 Relationship between IOCs.
    ---
    tags:
      - IOC Relations
    summary: Create IOC Relation (STIX 2.1)
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
              - relationship_type
            properties:
              related_ioc_ids:
                type: array
                items:
                  type: string
                description: Array of target IOC IDs to link
              relationship_type:
                type: string
                enum:
                  - indicates
                  - uses
                  - related-to
                  - derived-from
                  - duplicate-of
                  - based-on
                  - targets
                  - attributed-to
                  - mitigates
                  - compromises
                  - originates-from
                  - investigates
                  - remediates
                  - delivers
                  - drops
                  - communicates-with
                  - controls
                  - exploits
                description: STIX 2.1 relationship type
              description:
                type: string
                description: Optional description of the relationship
    responses:
      201:
        description: STIX Relationships created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            relationships:
              type: array
              items:
                type: object
                description: Created STIX Relationship objects
      400:
        description: Invalid request or invalid relationship type
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
    
    relationship_type = data.get('relationship_type', 'related-to')
    description = data.get('description')
    
    if not related_ids:
        return jsonify({'error': 'related_ioc_ids or related_ioc_id is required'}), 400
    
    if not isinstance(related_ids, list):
        return jsonify({'error': 'related_ioc_ids must be an array'}), 400
    
    # Validate relationship type
    if relationship_type not in STIX_RELATIONSHIP_TYPES:
        return jsonify({
            'error': f"Invalid relationship_type '{relationship_type}'. Must be one of: {', '.join(STIX_RELATIONSHIP_TYPES)}"
        }), 400
    
    # Build source_ref (add indicator-- prefix if not present)
    if ioc_id.startswith('indicator--'):
        source_ref = ioc_id
    else:
        source_ref = f"indicator--{ioc_id}"
    
    # Verify source IOC exists (IOCs are stored with indicator--uuid as _id)
    source_ioc = es.get('ioc', source_ref)
    if not source_ioc:
        return jsonify({'error': 'Source IOC not found'}), 404
    
    created_relationships = []
    
    for target_id in related_ids:
        # Build target_ref (add indicator-- prefix if not present)
        if target_id.startswith('indicator--'):
            target_ref = target_id
        else:
            target_ref = f"indicator--{target_id}"
        
        if target_ref == source_ref:
            continue  # Skip self-relations
        
        # Verify target IOC exists (IOCs are stored with indicator--uuid as _id)
        target_ioc = es.get('ioc', target_ref)
        if not target_ioc:
            continue  # Skip non-existent IOCs
        
        # Check if STIX relationship already exists (avoid duplicates)
        existing = es.search('stix_relationships', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'relationship_type': relationship_type}},
                        {'bool': {
                            'should': [
                                {
                                    'bool': {
                                        'must': [
                                            {'term': {'source_ref': source_ref}},
                                            {'term': {'target_ref': target_ref}}
                                        ]
                                    }
                                },
                                {
                                    'bool': {
                                        'must': [
                                            {'term': {'source_ref': target_ref}},
                                            {'term': {'target_ref': source_ref}}
                                        ]
                                    }
                                }
                            ],
                            'minimum_should_match': 1
                        }}
                    ]
                }
            },
            'size': 1
        })
        
        if existing['hits']['total']['value'] > 0:
            continue  # Relationship already exists
        
        # Create STIX 2.1 Relationship
        try:
            stix_rel = STIXRelationship.create(
                source_ref=source_ref,
                target_ref=target_ref,
                relationship_type=relationship_type,
                description=description
            )
            
            # Convert to dict with ELASLIP metadata
            rel_doc = stix_rel.to_dict_with_metadata(
                user_id=g.current_user.id,
                username=getattr(g.current_user, 'username', None)
            )
            
            # Use the STIX ID as the document ID (without relationship-- prefix for ES)
            doc_id = stix_rel.id.replace('relationship--', '')
            
            es.index('stix_relationships', doc_id, rel_doc)
            created_relationships.append(rel_doc)
            
        except ValueError as e:
            # Log error but continue with other relationships
            pass
    
    return jsonify({
        'message': f'Created {len(created_relationships)} STIX relationship(s)',
        'relationships': created_relationships
    }), 201


@ioc_relations_bp.route('/ioc/<ioc_id>/relations/<relation_id>', methods=['DELETE'])
@login_or_api_key_required
def delete_ioc_relation(ioc_id, relation_id):
    """
    Delete a STIX Relationship.
    ---
    tags:
      - IOC Relations
    summary: Delete IOC Relation (STIX 2.1)
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
        description: Relationship ID to delete (with or without relationship-- prefix)
    responses:
      200:
        description: Relationship deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      403:
        description: Relationship does not involve the specified IOC
      404:
        description: Relationship not found
    """
    es = ElasticsearchService()
    
    # Handle relation_id with or without relationship-- prefix
    if relation_id.startswith('relationship--'):
        doc_id = relation_id.replace('relationship--', '')
    else:
        doc_id = relation_id
    
    # Build source_ref for the IOC
    if ioc_id.startswith('indicator--'):
        ioc_ref = ioc_id
    else:
        ioc_ref = f"indicator--{ioc_id}"
    
    # Verify the relationship exists and involves this IOC
    relationship = es.get('stix_relationships', doc_id)
    if not relationship:
        return jsonify({'error': 'Relationship not found'}), 404
    
    rel_data = relationship['_source']
    if rel_data['source_ref'] != ioc_ref and rel_data['target_ref'] != ioc_ref:
        return jsonify({'error': 'This relationship does not involve the specified IOC'}), 403
    
    es.delete('stix_relationships', doc_id)
    
    return jsonify({'message': 'STIX Relationship deleted successfully'}), 200


@ioc_relations_bp.route('/api/stix/relationship-types', methods=['GET'])
@login_or_api_key_required
def get_relationship_types():
    """
    Get list of valid STIX 2.1 relationship types.
    ---
    tags:
      - IOC Relations
    summary: Get STIX Relationship Types
    responses:
      200:
        description: List of valid STIX 2.1 relationship types
        schema:
          type: object
          properties:
            relationship_types:
              type: array
              items:
                type: string
    """
    return jsonify({'relationship_types': STIX_RELATIONSHIP_TYPES}), 200
