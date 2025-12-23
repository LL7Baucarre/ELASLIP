"""API routes for Cases, Incidents, Timeline, Comments, and Snippets."""

from datetime import datetime
from flask import Blueprint, jsonify, request, abort
from flask_login import login_required, current_user
from app.auth import permission_required
from app.services.case_service import CaseService, IncidentService, TimelineService
from app.services.comment_service import CommentService, SnippetService
from app.services.audit_service import AuditService

bp = Blueprint('cases', __name__)

case_service = CaseService()
incident_service = IncidentService()
timeline_service = TimelineService()
comment_service = CommentService()
snippet_service = SnippetService()
audit_service = AuditService()


# ============== CASES ==============

@bp.route('/api/cases', methods=['GET'])
@login_required
@permission_required('case.view')
def list_cases():
    """
    List all cases.
    ---
    tags:
      - Cases
    parameters:
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 20
      - name: status
        in: query
        type: string
        enum: ['open', 'in-progress', 'on-hold', 'closed']
      - name: priority
        in: query
        type: string
        enum: ['low', 'medium', 'high', 'critical']
      - name: search
        in: query
        type: string
    responses:
      200:
        description: List of cases
        schema:
          properties:
            items:
              type: array
            total:
              type: integer
            page:
              type: integer
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    priority = request.args.get('priority')
    search = request.args.get('search')
    
    filters = {}
    if status:
        filters['status'] = status
    if priority:
        filters['priority'] = priority
    if search:
        filters['search'] = search
    
    result = case_service.list_cases(
        page=page, per_page=per_page, filters=filters if filters else None
    )
    return jsonify(result)


@bp.route('/api/cases/<case_id>', methods=['GET'])
@login_required
@permission_required('case.view')
def get_case(case_id):
    """
    Get a case by ID.
    ---
    tags:
      - Cases
    responses:
      200:
        description: Case details
      404:
        description: Case not found
    """
    case = case_service.get_case(case_id)
    if not case:
        abort(404, 'Case not found')
    return jsonify(case)


@bp.route('/api/cases', methods=['POST'])
@login_required
@permission_required('case.create')
def create_case():
    """Create a new case."""
    data = request.get_json()
    if not data or not data.get('title'):
        abort(400, 'Title is required')
    
    case = case_service.create_case(
        data, 
        user_id=current_user.id,
        username=current_user.username
    )
    
    audit_service.log(
        'create',
        entity_type='case',
        entity_id=case['id'],
        user_id=current_user.id,
        username=current_user.username,
        entity_name=case.get('title', 'Unknown')
    )
    
    return jsonify(case), 201


@bp.route('/api/cases/<case_id>', methods=['PUT'])
@login_required
@permission_required('case.edit')
def update_case(case_id):
    """Update a case."""
    data = request.get_json()
    case = case_service.update_case(
        case_id, data,
        user_id=current_user.id,
        username=current_user.username
    )
    if not case:
        abort(404, 'Case not found')
    
    audit_service.log(
        'update',
        entity_type='case',
        entity_id=case_id,
        user_id=current_user.id,
        username=current_user.username,
        changes=data
    )
    
    return jsonify(case)


@bp.route('/api/cases/<case_id>', methods=['DELETE'])
@login_required
@permission_required('case.delete')
def delete_case(case_id):
    """Delete a case."""
    case = case_service.get_case(case_id)
    if not case:
        abort(404, 'Case not found')
    
    case_service.delete_case(
        case_id,
        user_id=current_user.id,
        username=current_user.username
    )
    
    audit_service.log(
        'delete',
        entity_type='case',
        entity_id=case_id,
        user_id=current_user.id,
        username=current_user.username,
        entity_name=case.get('title', 'Unknown')
    )
    
    return jsonify({'success': True})


@bp.route('/api/cases/<case_id>/iocs', methods=['POST'])
@login_required
@permission_required('case.edit')
def add_ioc_to_case(case_id):
    """Add an IOC to a case."""
    data = request.get_json()
    ioc_id = data.get('ioc_id')
    if not ioc_id:
        abort(400, 'IOC ID is required')
    
    case = case_service.add_iocs_to_case(
        case_id, 
        [ioc_id],
        user_id=current_user.id,
        username=current_user.username
    )
    if not case:
        abort(404, 'Case not found')
    
    return jsonify({'success': True})


@bp.route('/api/cases/<case_id>/iocs/<ioc_id>', methods=['DELETE'])
@login_required
@permission_required('case.edit')
def remove_ioc_from_case(case_id, ioc_id):
    """Remove an IOC from a case."""
    case = case_service.remove_ioc_from_case(
        case_id, 
        ioc_id,
        user_id=current_user.id,
        username=current_user.username
    )
    if not case:
        abort(404, 'Case not found')
    return jsonify({'success': True})


@bp.route('/api/cases/<case_id>/incidents', methods=['GET'])
@login_required
@permission_required('case.view')
def get_case_incidents(case_id):
    """Get incidents linked to a case."""
    case = case_service.get_case(case_id)
    if not case:
        abort(404, 'Case not found')
    
    # Get incident IDs from the case and fetch full incident objects
    incident_ids = case.get('incident_ids', [])
    incidents = []
    for incident_id in incident_ids:
        incident = incident_service.get_incident(incident_id)
        if incident:
            incidents.append(incident)
    
    return jsonify({
        'items': incidents,
        'total': len(incidents)
    })


@bp.route('/api/cases/<case_id>/incidents', methods=['POST'])
@login_required
@permission_required('case.edit')
def link_incident_to_case(case_id):
    """Link an incident to a case."""
    data = request.get_json()
    incident_id = data.get('incident_id')
    if not incident_id:
        abort(400, 'Incident ID is required')
    
    success = case_service.link_incident(case_id, incident_id)
    if not success:
        abort(404, 'Case not found')
    
    return jsonify({'success': True})


@bp.route('/api/cases/stats', methods=['GET'])
@login_required
@permission_required('case.view')
def get_case_stats():
    """Get case statistics."""
    cases = case_service.list_cases(page=1, per_page=1000)
    stats = {
        'total_cases': cases.get('total', 0),
        'open_cases': len([c for c in cases.get('items', []) if c.get('status') == 'open']),
        'in_progress_cases': len([c for c in cases.get('items', []) if c.get('status') == 'in-progress']),
        'closed_cases': len([c for c in cases.get('items', []) if c.get('status') == 'closed']),
        'high_priority_cases': len([c for c in cases.get('items', []) if c.get('priority') in ['high', 'critical']])
    }
    return jsonify(stats)


# ============== INCIDENTS ==============

@bp.route('/api/incidents', methods=['GET'])
@login_required
@permission_required('incident.view')
def list_incidents():
    """
    List all incidents.
    ---
    tags:
      - Incidents
    parameters:
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 20
      - name: status
        in: query
        type: string
        enum: ['detected', 'contained', 'recovered', 'closed']
      - name: severity
        in: query
        type: string
        enum: ['low', 'medium', 'high', 'critical']
      - name: search
        in: query
        type: string
    responses:
      200:
        description: List of incidents
        schema:
          properties:
            items:
              type: array
            total:
              type: integer
            page:
              type: integer
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    severity = request.args.get('severity')
    search = request.args.get('search')
    
    filters = {}
    if status:
        filters['status'] = status
    if severity:
        filters['severity'] = severity
    if search:
        filters['search'] = search
    
    result = incident_service.list_incidents(
        page=page, per_page=per_page, filters=filters if filters else None
    )
    return jsonify(result)


@bp.route('/api/incidents/<incident_id>', methods=['GET'])
@login_required
@permission_required('incident.view')
def get_incident(incident_id):
    """
    Get an incident by ID.
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Incident details
      404:
        description: Incident not found
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    return jsonify(incident)


@bp.route('/api/incidents', methods=['POST'])
@login_required
@permission_required('incident.create')
def create_incident():
    """
    Create a new incident.
    ---
    tags:
      - Incidents
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            title:
              type: string
            description:
              type: string
            severity:
              type: string
              enum: ['low', 'medium', 'high', 'critical']
            case_id:
              type: string
    responses:
      201:
        description: Incident created successfully
      400:
        description: Invalid data provided
    """
    data = request.get_json()
    if not data or not data.get('title'):
        abort(400, 'Title is required')
    
    incident = incident_service.create_incident(
        data,
        user_id=current_user.id,
        username=current_user.username
    )
    
    audit_service.log(
        'create',
        entity_type='incident',
        entity_id=incident['id'],
        user_id=current_user.id,
        username=current_user.username,
        entity_name=incident.get('title', 'Unknown')
    )
    
    return jsonify(incident), 201


@bp.route('/api/incidents/<incident_id>', methods=['PUT'])
@login_required
@permission_required('incident.edit')
def update_incident(incident_id):
    """
    Update an incident.
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          properties:
            title:
              type: string
            description:
              type: string
            severity:
              type: string
              enum: ['low', 'medium', 'high', 'critical']
            status:
              type: string
              enum: ['detected', 'contained', 'recovered', 'closed']
    responses:
      200:
        description: Incident updated successfully
      404:
        description: Incident not found
    """
    data = request.get_json()
    incident = incident_service.update_incident(
        incident_id, data,
        user_id=current_user.id,
        username=current_user.username
    )
    if not incident:
        abort(404, 'Incident not found')
    
    audit_service.log(
        'update',
        entity_type='incident',
        entity_id=incident_id,
        user_id=current_user.id,
        username=current_user.username,
        changes=data
    )
    
    return jsonify(incident)


@bp.route('/api/incidents/<incident_id>', methods=['DELETE'])
@login_required
@permission_required('incident.delete')
def delete_incident(incident_id):
    """
    Delete an incident.
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Incident deleted successfully
      404:
        description: Incident not found
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    incident_service.delete_incident(
        incident_id,
        user_id=current_user.id,
        username=current_user.username
    )
    
    audit_service.log(
        'delete',
        entity_type='incident',
        entity_id=incident_id,
        user_id=current_user.id,
        username=current_user.username,
        entity_name=incident.get('title', 'Unknown')
    )
    
    return jsonify({'success': True})


@bp.route('/api/incidents/<incident_id>/iocs', methods=['POST'])
@login_required
@permission_required('incident.edit')
def add_ioc_to_incident(incident_id):
    """
    Add an IOC to an incident.
    ---
    tags:
      - Incidents
      - IOCs
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          properties:
            ioc_id:
              type: string
    responses:
      200:
        description: IOC added successfully
      400:
        description: IOC ID is required
      404:
        description: Incident not found
    """
    data = request.get_json()
    ioc_id = data.get('ioc_id')
    if not ioc_id:
        abort(400, 'IOC ID is required')
    
    success = incident_service.add_iocs_to_incident(incident_id, [ioc_id], current_user.id, current_user.username)
    if not success:
        abort(404, 'Incident not found')
    
    return jsonify({'success': True})


@bp.route('/api/incidents/<incident_id>/iocs/<ioc_id>', methods=['DELETE'])
@login_required
@permission_required('incident.edit')
def remove_ioc_from_incident(incident_id, ioc_id):
    """
    Remove an IOC from an incident.
    ---
    tags:
      - Incidents
      - IOCs
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: ioc_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: IOC removed successfully
      404:
        description: Incident not found
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    ioc_ids = incident.get('ioc_ids', [])
    if ioc_id in ioc_ids:
        ioc_ids.remove(ioc_id)
        incident_service.es.update('incidents', incident_id, {'doc': {'ioc_ids': ioc_ids}})
    
    return jsonify({'success': True})


@bp.route('/api/incidents/<incident_id>/report', methods=['PUT'])
@login_required
@permission_required('incident.edit')
def update_incident_report(incident_id):
    """
    Update incident report content (markdown).
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          properties:
            content:
              type: string
              description: Markdown content for the report
    responses:
      200:
        description: Report updated successfully
      400:
        description: Report content is required
      404:
        description: Incident not found
    """
    data = request.get_json()
    content = data.get('content')
    
    if content is None:
        abort(400, 'Report content is required')
    
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    incident_service.es.update('incidents', incident_id, {
        'doc': {
            'report_content': content,
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
    })
    
    return jsonify({'success': True})
    
    return jsonify({'success': True})


@bp.route('/api/incidents/<incident_id>/status', methods=['PUT'])
@login_required
@permission_required('incident.edit')
def update_incident_status(incident_id):
    """
    Update incident status.
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          properties:
            status:
              type: string
              enum: ['detected', 'contained', 'recovered', 'closed']
    responses:
      200:
        description: Status updated successfully
      400:
        description: Status is required
      404:
        description: Incident not found
    """
    data = request.get_json()
    status = data.get('status')
    
    if not status:
        abort(400, 'Status is required')
    
    incident = incident_service.update_status(
        incident_id, status,
        user_id=current_user.id,
        username=current_user.username
    )
    
    if not incident:
        abort(404, 'Incident not found')
    
    return jsonify(incident)


# ============== TIMELINE ==============

@bp.route('/api/timeline/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_timeline(entity_type, entity_id):
    """Get timeline for an entity."""
    # Check permission based on entity type
    if entity_type == 'case' and not current_user.has_permission('case.view'):
        abort(403)
    elif entity_type == 'incident' and not current_user.has_permission('incident.view'):
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Build the correct kwargs based on entity type
    kwargs = {'page': page, 'per_page': per_page}
    if entity_type == 'case':
        kwargs['case_id'] = entity_id
    elif entity_type == 'incident':
        kwargs['incident_id'] = entity_id
    
    result = timeline_service.get_timeline(**kwargs)
    return jsonify(result)


@bp.route('/api/timeline/<entity_type>/<entity_id>', methods=['POST'])
@login_required
def add_timeline_event(entity_type, entity_id):
    """Add a timeline event."""
    # Check permission based on entity type
    if entity_type == 'case' and not current_user.has_permission('case.edit'):
        abort(403)
    elif entity_type == 'incident' and not current_user.has_permission('incident.edit'):
        abort(403)
    
    data = request.get_json()
    
    # Set the correct ID field
    if entity_type == 'case':
        data['case_id'] = entity_id
    elif entity_type == 'incident':
        data['incident_id'] = entity_id
    
    event = timeline_service.add_event(
        data,
        user_id=current_user.id,
        username=current_user.username
    )
    
    return jsonify(event), 201


@bp.route('/api/timeline/event/<event_id>', methods=['GET'])
@login_required
def get_timeline_event(event_id):
    """Get a timeline event."""
    event = timeline_service.get_event(event_id)
    if not event:
        abort(404, 'Event not found')
    return jsonify(event)


@bp.route('/api/timeline/event/<event_id>', methods=['PUT'])
@login_required
def update_timeline_event(event_id):
    """Update a timeline event."""
    event = timeline_service.get_event(event_id)
    if not event:
        abort(404, 'Event not found')
    
    # Check if user can edit the parent entity
    if event.get('case_id') and not current_user.has_permission('case.edit'):
        abort(403)
    elif event.get('incident_id') and not current_user.has_permission('incident.edit'):
        abort(403)
    
    data = request.get_json()
    updated_event = timeline_service.update_event(event_id, data)
    return jsonify(updated_event)


@bp.route('/api/timeline/event/<event_id>', methods=['DELETE'])
@login_required
def delete_timeline_event(event_id):
    """Delete a timeline event."""
    # First get the event to check permissions
    event = timeline_service.get_event(event_id)
    if not event:
        abort(404, 'Event not found')
    
    # Check if user can edit the parent entity
    if event.get('case_id') and not current_user.has_permission('case.edit'):
        abort(403)
    elif event.get('incident_id') and not current_user.has_permission('incident.edit'):
        abort(403)
    
    timeline_service.delete_event(event_id)
    return jsonify({'success': True})


# ============== COMMENTS ==============

@bp.route('/api/comments/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_comments(entity_type, entity_id):
    """Get comments for an entity."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    result = comment_service.get_comments(
        entity_type, entity_id,
        page=page, per_page=per_page
    )
    return jsonify(result)


@bp.route('/api/comments/<entity_type>/<entity_id>', methods=['POST'])
@login_required
@permission_required('comment.create')
def create_comment(entity_type, entity_id):
    """Create a new comment."""
    data = request.get_json()
    content = data.get('content', '').strip()
    parent_id = data.get('parent_id')
    
    if not content:
        abort(400, 'Content is required')
    
    comment = comment_service.create_comment(
        entity_type, entity_id, content,
        user_id=current_user.id,
        username=current_user.username,
        parent_id=parent_id
    )
    
    return jsonify(comment), 201


@bp.route('/api/comments/<comment_id>', methods=['PUT'])
@login_required
@permission_required('comment.edit')
def update_comment(comment_id):
    """Update a comment."""
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        abort(400, 'Content is required')
    
    comment = comment_service.update_comment(
        comment_id, content,
        user_id=current_user.id
    )
    
    if not comment:
        abort(404, 'Comment not found or not authorized')
    
    return jsonify(comment)


@bp.route('/api/comments/<comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    """Delete a comment."""
    is_admin = current_user.has_permission('comment.delete')
    success = comment_service.delete_comment(
        comment_id,
        user_id=current_user.id,
        is_admin=is_admin
    )
    
    if not success:
        abort(404, 'Comment not found or not authorized')
    
    return jsonify({'success': True})


@bp.route('/api/comments/<entity_type>/<entity_id>/count', methods=['GET'])
@login_required
def get_comment_count(entity_type, entity_id):
    """Get comment count for an entity."""
    count = comment_service.get_comment_count(entity_type, entity_id)
    return jsonify({'count': count})


# ============== SNIPPETS ==============

@bp.route('/api/snippets', methods=['GET'])
@login_required
@permission_required('snippet.view')
def list_snippets():
    """List snippets available to the user."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    category = request.args.get('category')
    search = request.args.get('search')
    include_global = request.args.get('include_global', 'true').lower() == 'true'
    
    result = snippet_service.list_snippets(
        user_id=current_user.id,
        page=page, per_page=per_page,
        category=category, search=search,
        include_global=include_global
    )
    return jsonify(result)


@bp.route('/api/snippets/<snippet_id>', methods=['GET'])
@login_required
@permission_required('snippet.view')
def get_snippet(snippet_id):
    """Get a snippet by ID."""
    snippet = snippet_service.get_snippet(snippet_id)
    if not snippet:
        abort(404, 'Snippet not found')
    
    # Check access
    if not snippet['is_global'] and snippet['created_by_id'] != current_user.id:
        if not current_user.has_permission('snippet.manage_global'):
            abort(403)
    
    return jsonify(snippet)


@bp.route('/api/snippets', methods=['POST'])
@login_required
@permission_required('snippet.create')
def create_snippet():
    """Create a new snippet."""
    data = request.get_json()
    if not data or not data.get('title') or not data.get('content'):
        abort(400, 'Title and content are required')
    
    # Only admins can create global snippets
    if data.get('is_global') and not current_user.has_permission('snippet.manage_global'):
        data['is_global'] = False
    
    snippet = snippet_service.create_snippet(
        data,
        user_id=current_user.id,
        username=current_user.username
    )
    
    return jsonify(snippet), 201


@bp.route('/api/snippets/<snippet_id>', methods=['PUT'])
@login_required
@permission_required('snippet.edit')
def update_snippet(snippet_id):
    """Update a snippet."""
    data = request.get_json()
    
    # Only admins can make snippets global
    if 'is_global' in data and not current_user.has_permission('snippet.manage_global'):
        del data['is_global']
    
    is_admin = current_user.has_permission('snippet.manage_global')
    snippet = snippet_service.update_snippet(
        snippet_id, data,
        user_id=current_user.id,
        is_admin=is_admin
    )
    
    if not snippet:
        abort(404, 'Snippet not found or not authorized')
    
    return jsonify(snippet)


@bp.route('/api/snippets/<snippet_id>', methods=['DELETE'])
@login_required
@permission_required('snippet.delete')
def delete_snippet(snippet_id):
    """Delete a snippet."""
    is_admin = current_user.has_permission('snippet.manage_global')
    success = snippet_service.delete_snippet(
        snippet_id,
        user_id=current_user.id,
        is_admin=is_admin
    )
    
    if not success:
        abort(404, 'Snippet not found or not authorized')
    
    return jsonify({'success': True})


@bp.route('/api/snippets/<snippet_id>/use', methods=['POST'])
@login_required
@permission_required('snippet.view')
def use_snippet(snippet_id):
    """Record usage of a snippet and return its content."""
    snippet = snippet_service.get_snippet(snippet_id)
    if not snippet:
        abort(404, 'Snippet not found')
    
    # Check access
    if not snippet['is_global'] and snippet['created_by_id'] != current_user.id:
        if not current_user.has_permission('snippet.manage_global'):
            abort(403)
    
    snippet_service.increment_usage(snippet_id)
    return jsonify({'content': snippet['content']})


@bp.route('/api/snippets/categories', methods=['GET'])
@login_required
@permission_required('snippet.view')
def get_snippet_categories():
    """Get snippet categories with counts."""
    categories = snippet_service.get_categories()
    return jsonify({'categories': categories})


@bp.route('/api/snippets/<snippet_id>/export', methods=['GET'])
@login_required
@permission_required('snippet.view')
def export_snippet(snippet_id):
    """Export a snippet as markdown."""
    markdown = snippet_service.export_snippet(snippet_id)
    if not markdown:
        abort(404, 'Snippet not found')
    
    return markdown, 200, {'Content-Type': 'text/markdown'}


@bp.route('/api/snippets/import', methods=['POST'])
@login_required
@permission_required('snippet.create')
def import_snippet():
    """Import a snippet from markdown."""
    data = request.get_json()
    content = data.get('content', '')
    title = data.get('title', 'Imported Snippet')
    category = data.get('category', 'other')
    
    if not content:
        abort(400, 'Content is required')
    
    snippet = snippet_service.import_snippet(
        content, title, category,
        user_id=current_user.id,
        username=current_user.username
    )
    
    return jsonify(snippet), 201
