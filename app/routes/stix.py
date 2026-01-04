# -*- coding: utf-8 -*-
"""
STIX 2.1 Object Routes
API endpoints for managing STIX Domain Objects (SDO)
"""

import json
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user

from app.decorators import permission_required
from app.services.stix_service import STIXService
from app.services.audit_service import AuditService
from app.services.elasticsearch_service import ElasticsearchService

stix_bp = Blueprint('stix', __name__)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@stix_bp.route('/api/stix/objects', methods=['POST'])
@permission_required('ioc.create')
def create_stix_object():
    """
    Create a new STIX Domain Object
    
    Expected JSON body:
    {
        "type": "indicator|malware|threat-actor|...",
        "name": "Object name",
        "description": "Description",
        // Type-specific fields...
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        sdo_type = data.get("type")
        if not sdo_type:
            return jsonify({"error": "Missing 'type' field"}), 400
        
        if sdo_type not in STIXService.SDO_TYPES:
            return jsonify({
                "error": f"Unsupported SDO type: {sdo_type}",
                "supported_types": list(STIXService.SDO_TYPES.keys())
            }), 400
        
        # Create the object
        stix_object = STIXService.create_sdo(
            sdo_type=sdo_type,
            data=data,
            user_id=str(current_user.id),
            username=current_user.username
        )
        
        # Audit log
        AuditService().log(
            action="create",
            entity_type="stix_object",
            entity_id=stix_object["id"],
            entity_name=data.get("name", sdo_type),
            user_id=str(current_user.id),
            username=current_user.username
        )
        
        return jsonify({
            "success": True,
            "message": f"STIX {sdo_type} created successfully",
            "object": stix_object
        }), 201
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to create STIX object: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects', methods=['GET'])
@permission_required('ioc.view')
def list_stix_objects():
    """
    List STIX objects with pagination and filtering
    
    Query params:
    - type: Filter by object type
    - page: Page number (default 1)
    - size: Page size (default 20)
    - search: Search term
    - sort: Sort field (default: modified)
    - order: Sort order (asc/desc, default: desc)
    """
    try:
        sdo_type = request.args.get('type')
        page = int(request.args.get('page', 1))
        size = int(request.args.get('size', 20))
        search = request.args.get('search')
        sort_by = request.args.get('sort', 'modified')
        sort_order = request.args.get('order', 'desc')
        
        result = STIXService.list_sdos(
            sdo_type=sdo_type,
            page=page,
            size=size,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"Failed to list STIX objects: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>', methods=['GET'])
@permission_required('ioc.view')
def get_stix_object(stix_id):
    """Get a single STIX object by ID"""
    try:
        stix_object = STIXService.get_sdo(stix_id)
        
        if not stix_object:
            return jsonify({"error": "STIX object not found"}), 404
        
        return jsonify(stix_object)
        
    except Exception as e:
        return jsonify({"error": f"Failed to get STIX object: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>', methods=['PUT'])
@permission_required('ioc.edit')
def update_stix_object(stix_id):
    """Update a STIX object"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Don't allow changing type or id
        data.pop('type', None)
        data.pop('id', None)
        data.pop('created', None)
        data.pop('spec_version', None)
        
        updated = STIXService.update_sdo(stix_id, data)
        
        if not updated:
            return jsonify({"error": "STIX object not found"}), 404
        
        # Audit log
        AuditService().log(
            action="update",
            entity_type="stix_object",
            entity_id=stix_id,
            changes=data,
            user_id=str(current_user.id),
            username=current_user.username
        )
        
        return jsonify({
            "success": True,
            "message": "STIX object updated successfully",
            "object": updated
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to update STIX object: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>', methods=['DELETE'])
@permission_required('ioc.delete')
def delete_stix_object(stix_id):
    """Delete a STIX object and its relationships"""
    try:
        # Get object info before deletion for audit
        stix_object = STIXService.get_sdo(stix_id)
        
        if not stix_object:
            return jsonify({"error": "STIX object not found"}), 404
        
        success = STIXService.delete_sdo(stix_id)
        
        if success:
            # Audit log
            AuditService().log(
                action="delete",
                entity_type="stix_object",
                entity_id=stix_id,
                entity_name=stix_object.get("name", stix_object.get("type")),
                user_id=str(current_user.id),
                username=current_user.username
            )
            
            return jsonify({
                "success": True,
                "message": "STIX object deleted successfully"
            })
        else:
            return jsonify({"error": "Failed to delete STIX object"}), 500
        
    except Exception as e:
        return jsonify({"error": f"Failed to delete STIX object: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>/bundle', methods=['GET'])
@login_required
@permission_required('ioc.view')
def export_stix_bundle(stix_id):
    """Export a STIX object with all its relationships as a STIX 2.1 Bundle"""
    try:
        bundle = STIXService.export_bundle(stix_id)
        
        if not bundle:
            return jsonify({"error": "STIX object not found"}), 404
        
        return jsonify(bundle)
        
    except Exception as e:
        return jsonify({"error": f"Failed to export bundle: {str(e)}"}), 500


# ============================================================================
# RELATIONSHIPS API
# ============================================================================

@stix_bp.route('/api/stix/relationships', methods=['POST'])
@permission_required('ioc.create')
def create_relationship():
    """
    Create a STIX relationship between two objects
    
    Expected JSON body:
    {
        "source_ref": "indicator--<uuid>",
        "target_ref": "malware--<uuid>",
        "relationship_type": "indicates",
        "description": "Optional description",
        "start_time": "2024-01-01T00:00:00.000Z",
        "stop_time": "2024-12-31T23:59:59.999Z"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        source_ref = data.get("source_ref")
        target_ref = data.get("target_ref")
        relationship_type = data.get("relationship_type")
        
        if not all([source_ref, target_ref, relationship_type]):
            return jsonify({"error": "Missing required fields: source_ref, target_ref, relationship_type"}), 400
        
        # Validate objects exist
        source = STIXService.get_sdo(source_ref)
        target = STIXService.get_sdo(target_ref)
        
        if not source:
            return jsonify({"error": f"Source object not found: {source_ref}"}), 404
        if not target:
            return jsonify({"error": f"Target object not found: {target_ref}"}), 404
        
        relationship = STIXService.create_relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            description=data.get("description"),
            start_time=data.get("start_time"),
            stop_time=data.get("stop_time"),
            user_id=str(current_user.id),
            username=current_user.username
        )
        
        # Audit log
        AuditService().log(
            action="create",
            entity_type="stix_relationship",
            entity_id=relationship["id"],
            entity_name=f"{relationship_type}: {source_ref} -> {target_ref}",
            user_id=str(current_user.id),
            username=current_user.username
        )
        
        return jsonify({
            "success": True,
            "message": "Relationship created successfully",
            "relationship": relationship
        }), 201
        
    except Exception as e:
        return jsonify({"error": f"Failed to create relationship: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>/relationships', methods=['GET'])
@permission_required('ioc.view')
def get_object_relationships(stix_id):
    """Get all relationships for a STIX object"""
    try:
        direction = request.args.get('direction', 'both')
        relationships = STIXService.get_relationships(stix_id, direction)
        
        return jsonify({
            "stix_id": stix_id,
            "count": len(relationships),
            "relationships": relationships
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to get relationships: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>/related', methods=['GET'])
@permission_required('ioc.view')
def get_related_objects(stix_id):
    """Get all related objects and relationships for a STIX object"""
    try:
        related_objects, relationships = STIXService.get_related_objects(stix_id)
        
        return jsonify({
            "stix_id": stix_id,
            "related_objects": related_objects,
            "relationships": relationships
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to get related objects: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/<stix_id>/linked-entities', methods=['GET'])
@permission_required('ioc.view')
def get_linked_entities(stix_id):
    """Get all cases and incidents that contain this STIX object"""
    try:
        es = ElasticsearchService()
        cases = []
        incidents = []
        
        # Find cases containing this STIX object
        try:
            case_results = es.search('cases', {
                'size': 100,
                'query': {
                    'bool': {
                        'should': [
                            {'term': {'ioc_ids': stix_id}}
                        ]
                    }
                }
            })
            for hit in case_results.get('hits', {}).get('hits', []):
                cases.append({
                    'id': hit['_id'],
                    'title': hit['_source'].get('title', 'Unknown Case'),
                    'status': hit['_source'].get('status', 'unknown'),
                    'entity_type': 'case'
                })
        except:
            pass
        
        # Find incidents containing this STIX object
        try:
            incident_results = es.search('incidents', {
                'size': 100,
                'query': {
                    'bool': {
                        'should': [
                            {'term': {'ioc_ids': stix_id}}
                        ]
                    }
                }
            })
            for hit in incident_results.get('hits', {}).get('hits', []):
                incidents.append({
                    'id': hit['_id'],
                    'title': hit['_source'].get('title', 'Unknown Incident'),
                    'severity': hit['_source'].get('severity', 'unknown'),
                    'entity_type': 'incident'
                })
        except:
            pass
        
        return jsonify({
            'stix_id': stix_id,
            'cases': cases,
            'incidents': incidents,
            'total_cases': len(cases),
            'total_incidents': len(incidents)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to get linked entities: {str(e)}"}), 500


@stix_bp.route('/api/stix/relationships/<rel_id>', methods=['DELETE'])
@permission_required('ioc.delete')
def delete_relationship(rel_id):
    """Delete a STIX relationship"""
    try:
        success = STIXService.delete_relationship(rel_id)
        
        if success:
            AuditService().log(
                action="delete",
                entity_type="stix_relationship",
                entity_id=rel_id,
                user_id=str(current_user.id),
                username=current_user.username
            )
            
            return jsonify({
                "success": True,
                "message": "Relationship deleted successfully"
            })
        else:
            return jsonify({"error": "Relationship not found or failed to delete"}), 404
        
    except Exception as e:
        return jsonify({"error": f"Failed to delete relationship: {str(e)}"}), 500


# ============================================================================
# SEARCH & UTILITY API
# ============================================================================

@stix_bp.route('/api/stix/search', methods=['GET'])
@permission_required('ioc.view')
def search_stix_objects():
    """
    Search STIX objects
    
    Query params:
    - q: Search query (required)
    - types: Comma-separated list of object types to search
    - size: Max results (default 50)
    """
    try:
        query = request.args.get('q')
        if not query:
            return jsonify({"error": "Missing search query 'q'"}), 400
        
        types = request.args.get('types')
        sdo_types = types.split(',') if types else None
        size = int(request.args.get('size', 50))
        
        results = STIXService.search_sdos(query, sdo_types, size)
        
        return jsonify({
            "query": query,
            "count": len(results),
            "results": results
        })
        
    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}"}), 500


@stix_bp.route('/api/stix/objects/available', methods=['GET'])
@permission_required('ioc.view')
def get_available_for_linking():
    """
    Get available STIX objects for linking (creating relationships)
    
    Query params:
    - exclude: Object ID to exclude from results
    - search: Optional search filter
    - size: Max results (default 100)
    """
    try:
        exclude_id = request.args.get('exclude')
        search = request.args.get('search')
        size = int(request.args.get('size', 100))
        
        results = STIXService.get_available_objects_for_linking(exclude_id, search, size)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": f"Failed to get available objects: {str(e)}"}), 500


@stix_bp.route('/api/stix/types', methods=['GET'])
@permission_required('ioc.view')
def get_sdo_types():
    """Get available STIX SDO types and their field specifications"""
    return jsonify({
        "sdo_types": STIXService.SDO_TYPES,
        "relationship_types": STIXService.RELATIONSHIP_TYPES
    })


# ============================================================================
# WEB PAGES
# ============================================================================

@stix_bp.route('/stix/add', methods=['GET'])
@login_required
def add_stix_object_page():
    """Render the STIX object creation form"""
    return render_template('stix/add.html',
                          sdo_types=STIXService.SDO_TYPES,
                          relationship_types=STIXService.RELATIONSHIP_TYPES)


@stix_bp.route('/stix/objects')
@login_required
def list_stix_objects_page():
    """Render the STIX objects list page"""
    return render_template('stix/list.html',
                          sdo_types=STIXService.SDO_TYPES)


@stix_bp.route('/stix/graph')
@login_required
def stix_graph_page():
    """Render the STIX objects graph visualization page"""
    return render_template('stix/graph.html')


@stix_bp.route('/stix/objects/<stix_id>')
@login_required
def view_stix_object_page(stix_id):
    """Render the STIX object detail page"""
    stix_object = STIXService.get_sdo(stix_id)
    
    if not stix_object:
        flash('STIX object not found', 'error')
        return redirect(url_for('stix.list_stix_objects_page'))
    
    related_objects, relationships = STIXService.get_related_objects(stix_id)
    
    return render_template('stix/detail.html',
                          stix_object=stix_object,
                          related_objects=related_objects,
                          relationships=relationships,
                          relationship_types=STIXService.RELATIONSHIP_TYPES)


@stix_bp.route('/stix/objects/<stix_id>/edit')
@login_required
def edit_stix_object_page(stix_id):
    """Render the STIX object edit page"""
    stix_object = STIXService.get_sdo(stix_id)
    
    if not stix_object:
        flash('STIX object not found', 'error')
        return redirect(url_for('stix.list_stix_objects_page'))
    
    return render_template('stix/edit.html',
                          stix_object=stix_object,
                          sdo_types=STIXService.SDO_TYPES,
                          relationship_types=STIXService.RELATIONSHIP_TYPES)

