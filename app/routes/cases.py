"""API routes for Cases, Incidents, Timeline, Comments, and Snippets."""

from datetime import datetime
from flask import Blueprint, jsonify, request, abort, current_app
from flask_login import login_required, current_user
from app.auth import permission_required
from app.services.case_service import CaseService, IncidentService, TimelineService
from app.services.comment_service import CommentService, SnippetService
from app.services.audit_service import AuditService
from app.services.elasticsearch_service import ElasticsearchService
from app.utils.request_helpers import get_pagination_params, build_filters_dict
import logging
logger = logging.getLogger(__name__)

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
      - name: sort
        in: query
        type: string
        description: 'Sort field and direction: field_asc or field_desc'
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
    page, per_page = get_pagination_params(default_per_page=20)
    sort = request.args.get('sort', 'created_desc')
    
    filters = build_filters_dict({
        'status': None,
        'priority': None,
        'search': None
    })
    
    # Normalize status: convert underscores to hyphens
    if filters and filters.get('status'):
        filters['status'] = filters['status'].replace('_', '-')
    
    result = case_service.list_cases(
        page=page, per_page=per_page, filters=filters if filters else None, sort=sort
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
    parameters:
      - in: path
        name: case_id
        type: string
        required: true
        description: Case ID
    responses:
      200:
        description: Case details
        schema:
          type: object
          properties:
            id:
              type: string
            title:
              type: string
            description:
              type: string
            status:
              type: string
            created_at:
              type: string
            created_by:
              type: string
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
    
    # Dispatch webhook for case creation
    try:
        from app.tasks.webhook_tasks import dispatch_webhook
        dispatch_webhook.delay('case.created', {
            'case_id': case['id'],
            'title': case.get('title'),
            'description': case.get('description'),
            'status': case.get('status'),
            'severity': case.get('severity'),
            'created_by': current_user.username,
            'created_at': case.get('created_at'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        current_app.logger.warning(f"Failed to dispatch case creation webhook: {str(e)}")
    
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
    
    # Dispatch webhook for case update
    try:
        from app.tasks.webhook_tasks import dispatch_webhook
        dispatch_webhook.delay('case.updated', {
            'case_id': case['id'],
            'title': case.get('title'),
            'description': case.get('description'),
            'status': case.get('status'),
            'severity': case.get('severity'),
            'updated_by': current_user.username,
            'updated_at': case.get('updated_at'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        current_app.logger.warning(f"Failed to dispatch case update webhook: {str(e)}")
    
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


@bp.route('/api/incidents/<incident_id>/cases', methods=['GET'])
@login_required
@permission_required('incident.view')
def get_incident_cases(incident_id):
    """Get cases linked to an incident."""
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    # Query Elasticsearch for cases that have this incident in their incident_ids
    es = ElasticsearchService()
    try:
        query = {
            'query': {
                'terms': {
                    'incident_ids': [incident_id]
                }
            },
            'size': 100
        }
        result = es.search('cases', query)
        cases = []
        for hit in result.get('hits', {}).get('hits', []):
            case = hit['_source']
            case['id'] = hit['_id']
            cases.append(case)
        
        return jsonify({
            'items': cases,
            'total': len(cases)
        })
    except Exception as e:
        print(f'Error searching for cases: {e}')
        return jsonify({
            'items': [],
            'total': 0
        })


@bp.route('/api/cases/stats', methods=['GET'])
@login_required
@permission_required('case.view')
def get_case_stats():
    """Get case statistics using Elasticsearch aggregation."""
    es = ElasticsearchService()
    
    # Use Elasticsearch aggregation for accurate counts
    result = es.aggregate('cases', {
        'by_status': {
            'terms': {'field': 'status.keyword', 'size': 10}
        },
        'by_priority': {
            'terms': {'field': 'priority.keyword', 'size': 10}
        }
    })
    
    stats = {
        'total': es.count('cases'),
        'by_status': {},
        'by_priority': {}
    }
    
    aggs = result.get('aggregations', {})
    
    for bucket in aggs.get('by_status', {}).get('buckets', []):
        stats['by_status'][bucket['key']] = bucket['doc_count']
    
    for bucket in aggs.get('by_priority', {}).get('buckets', []):
        stats['by_priority'][bucket['key']] = bucket['doc_count']
    
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
      - name: sort
        in: query
        type: string
        description: 'Sort field and direction: field_asc or field_desc'
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
    page, per_page = get_pagination_params(default_per_page=20)
    sort = request.args.get('sort', 'created_desc')
    
    filters = build_filters_dict({
        'status': None,
        'severity': None,
        'category': None,
        'search': None
    })
    
    result = incident_service.list_incidents(
        page=page, per_page=per_page, filters=filters if filters else None, sort=sort
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
    
    # Dispatch webhook for incident creation
    try:
        from app.tasks.webhook_tasks import dispatch_webhook
        dispatch_webhook.delay('incident.created', {
            'incident_id': incident['id'],
            'title': incident.get('title'),
            'description': incident.get('description'),
            'status': incident.get('status'),
            'severity': incident.get('severity'),
            'created_by': current_user.username,
            'created_at': incident.get('created_at'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        current_app.logger.warning(f"Failed to dispatch incident creation webhook: {str(e)}")
    
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
    
    # Dispatch webhook for incident update
    try:
        from app.tasks.webhook_tasks import dispatch_webhook
        dispatch_webhook.delay('incident.updated', {
            'incident_id': incident['id'],
            'title': incident.get('title'),
            'description': incident.get('description'),
            'status': incident.get('status'),
            'severity': incident.get('severity'),
            'updated_by': current_user.username,
            'updated_at': incident.get('updated_at'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        current_app.logger.warning(f"Failed to dispatch incident update webhook: {str(e)}")
    
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


@bp.route('/api/incidents/<incident_id>/checklists', methods=['POST'])
@login_required
@permission_required('incident.edit')
def add_checklist_to_incident(incident_id):
    """
    Add a checklist to an incident (created from template).
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
            template_id:
              type: string
              description: ID of checklist template to create from
            title:
              type: string
              description: Custom title for the checklist (optional, defaults to template name)
    responses:
      200:
        description: Checklist added successfully
      404:
        description: Incident or template not found
    """
    from app.services.checklist_service import ChecklistService
    from app.services.checklist_template_service import ChecklistTemplateService
    
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    data = request.get_json()
    template_id = data.get('template_id')
    
    if not template_id:
        abort(400, 'template_id is required')
    
    # Get the template
    template_service = ChecklistTemplateService()
    template = template_service.get_template(template_id)
    if not template:
        abort(404, 'Template not found')
    
    # Create a new checklist from the template
    checklist_service = ChecklistService()
    checklist = checklist_service.create_checklist(
        title=data.get('title') or template['name'],  # Use custom title or template name
        description=template.get('description', ''),
        created_by=current_user.username,
        created_by_id=current_user.id,
        items=template.get('items', []),
        tags=template.get('tags', []),
        campaigns=template.get('campaigns', []),
        related_incidents=[incident_id]
    )
    
    # Add checklist to incident
    checklist_ids = incident.get('checklist_ids', [])
    if checklist['id'] not in checklist_ids:
        checklist_ids.append(checklist['id'])
        incident_service.update_incident(
            incident_id,
            {'checklist_ids': checklist_ids},
            user_id=current_user.id,
            username=current_user.username
        )
    
    audit_service.log(
        action='create',
        entity_type='checklist',
        entity_id=checklist['id'],
        entity_name=checklist['title'],
        user_id=current_user.id,
        username=current_user.username,
        changes={'incident_id': incident_id, 'template_id': template_id}
    )
    
    return jsonify(checklist)


@bp.route('/api/incidents/<incident_id>/checklists/<checklist_id>', methods=['DELETE'])
@login_required
@permission_required('incident.edit')
def remove_checklist_from_incident(incident_id, checklist_id):
    """
    Remove a checklist from an incident.
    ---
    tags:
      - Incidents
    parameters:
      - name: incident_id
        in: path
        type: string
        required: true
      - name: checklist_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Checklist removed successfully
      404:
        description: Incident not found
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        abort(404, 'Incident not found')
    
    # Remove checklist ID from incident
    checklist_ids = incident.get('checklist_ids', [])
    if checklist_id in checklist_ids:
        checklist_ids.remove(checklist_id)
        incident_service.update_incident(
            incident_id,
            {'checklist_ids': checklist_ids},
            user_id=current_user.id,
            username=current_user.username
        )
    
    audit_service.log(
        action='update',
        entity_type='incident',
        entity_id=incident_id,
        user_id=current_user.id,
        username=current_user.username,
        changes={'removed_checklist_id': checklist_id}
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
@permission_required('comment.view')
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
@permission_required('comment.view')
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
    page, per_page = get_pagination_params(default_per_page=50)
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


# ============== GRAPH DATA ENDPOINTS ==============

@bp.route('/api/cases/<case_id>/graph-data')
@login_required
def get_case_graph_data(case_id):
    """Get graph data for a specific case and its relations (IOCs, related cases/incidents)."""
    from app.services.ioc_service import IOCService
    
    nodes = []
    edges = []
    edge_set = set()
    node_ids = set()
    
    # Get the main case
    case = case_service.get_case(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Add main case as central node - ALWAYS added, no try/except
    nodes.append({
        'data': {
            'id': case_id,
            'label': str(case.get('title', 'Unknown Case')),
            'entity_type': 'case',
            'status': case.get('status', 'unknown')
        },
        'classes': 'case'
    })
    node_ids.add(case_id)
    
    # Get all IOCs in this case
    ioc_ids = case.get('ioc_ids', [])
    current_app.logger.info(f"Case {case_id} has {len(ioc_ids)} IOCs: {ioc_ids}")
    
    ioc_service = IOCService()
    
    # Load IOCs
    for ioc_id in ioc_ids:
        try:
            ioc = ioc_service.get(ioc_id)
            if ioc:
                nodes.append({
                    'data': {
                        'id': ioc['id'],
                        'label': str(ioc.get('ioc_value', ioc.get('value', 'Unknown'))),
                        'type': str(ioc.get('ioc_type', 'unknown')),
                        'threat_level': str(ioc.get('threat_level', 'unknown')),
                        'confidence': str(ioc.get('confidence', '')),
                        'tlp': str(ioc.get('tlp', '')),
                        'entity_type': 'ioc'
                    },
                    'classes': f"ioc-{ioc.get('ioc_type', 'unknown').replace('-', '_')}"
                })
                node_ids.add(ioc_id)
                
                # Add edge from case to IOC
                edge_id = f"{case_id}-{ioc_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': case_id,
                            'target': ioc_id,
                            'label': 'contains-ioc'
                        },
                        'classes': 'relation-contains_ioc'
                    })
        except:
            pass
    
    # Get other cases that share IOCs with this case
    try:
        all_cases = case_service.es.search(
            'cases',
            {'size': 1000, 'query': {'match_all': {}}}
        )
        
        for hit in all_cases.get('hits', {}).get('hits', []):
            other_case_id = hit.get('_id')
            if other_case_id == case_id:
                continue
            
            other_case_data = hit.get('_source', {})
            other_ioc_ids = other_case_data.get('ioc_ids', [])
            
            # Check if they share any IOCs
            shared_iocs = set(ioc_ids) & set(other_ioc_ids)
            if shared_iocs:
                if other_case_id not in node_ids:
                    nodes.append({
                        'data': {
                            'id': other_case_id,
                            'label': str(other_case_data.get('title', 'Unknown Case')),
                            'entity_type': 'case',
                            'status': other_case_data.get('status', 'unknown')
                        },
                        'classes': 'case'
                    })
                    node_ids.add(other_case_id)
                
                edge_id = f"{case_id}-{other_case_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': case_id,
                            'target': other_case_id,
                            'label': f'shares-{len(shared_iocs)}-iocs'
                        },
                        'classes': 'relation-shares_iocs'
                    })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch related cases: {str(e)}")
    
    # Get incidents that share IOCs with this case
    try:
        all_incidents = case_service.es.search(
            'incidents',
            {'size': 1000, 'query': {'match_all': {}}}
        )
        
        for hit in all_incidents.get('hits', {}).get('hits', []):
            incident_id = hit.get('_id')
            incident_data = hit.get('_source', {})
            incident_ioc_ids = incident_data.get('ioc_ids', [])
            
            # Check if they share any IOCs
            shared_iocs = set(ioc_ids) & set(incident_ioc_ids)
            if shared_iocs:
                if incident_id not in node_ids:
                    nodes.append({
                        'data': {
                            'id': incident_id,
                            'label': str(incident_data.get('title', 'Unknown Incident')),
                            'entity_type': 'incident',
                            'severity': incident_data.get('severity', 'unknown')
                        },
                        'classes': 'incident'
                    })
                    node_ids.add(incident_id)
                
                edge_id = f"{case_id}-{incident_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': case_id,
                            'target': incident_id,
                            'label': f'shares-{len(shared_iocs)}-iocs'
                        },
                        'classes': 'relation-shares_iocs'
                    })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch incidents: {str(e)}")
    
    # Always return nodes and edges, at least with the case node
    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'count': len(nodes)
    })


@bp.route('/api/incidents/<incident_id>/graph-data')
@login_required
def get_incident_graph_data(incident_id):
    """Get graph data for a specific incident and its relations (IOCs, related cases/incidents)."""
    from app.services.ioc_service import IOCService
    
    nodes = []
    edges = []
    edge_set = set()
    node_ids = set()
    
    # Get the main incident
    incident = incident_service.get_incident(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    # Add main incident as central node - ALWAYS added, no try/except
    nodes.append({
        'data': {
            'id': incident_id,
            'label': str(incident.get('title', 'Unknown Incident')),
            'entity_type': 'incident',
            'severity': incident.get('severity', 'unknown')
        },
        'classes': 'incident'
    })
    node_ids.add(incident_id)
    
    # Get all IOCs in this incident
    ioc_ids = incident.get('ioc_ids', [])
    ioc_service = IOCService()
    
    # Load IOCs - wrapped in try/except, but doesn't prevent returning at least the incident
    try:
        for ioc_id in ioc_ids:
            try:
                ioc = ioc_service.get(ioc_id)
                if ioc:
                    nodes.append({
                        'data': {
                            'id': ioc['id'],
                            'label': str(ioc.get('ioc_value', ioc.get('value', 'Unknown'))),
                            'type': str(ioc.get('ioc_type', 'unknown')),
                            'threat_level': str(ioc.get('threat_level', 'unknown')),
                            'confidence': str(ioc.get('confidence', '')),
                            'tlp': str(ioc.get('tlp', '')),
                            'entity_type': 'ioc'
                        },
                        'classes': f"ioc-{ioc.get('ioc_type', 'unknown').replace('-', '_')}"
                    })
                    node_ids.add(ioc_id)
                    
                    # Add edge from incident to IOC
                    edge_id = f"{incident_id}-{ioc_id}"
                    if edge_id not in edge_set:
                        edge_set.add(edge_id)
                        edges.append({
                            'data': {
                                'id': edge_id,
                                'source': incident_id,
                                'target': ioc_id,
                                'label': 'contains-ioc'
                            },
                            'classes': 'relation-contains_ioc'
                        })
            except:
                pass
        
        # Get cases that share IOCs with this incident
        all_cases = case_service.es.search(
            'cases',
            {'size': 1000, 'query': {'match_all': {}}}
        )
        
        for hit in all_cases.get('hits', {}).get('hits', []):
            case_id = hit.get('_id')
            case_data = hit.get('_source', {})
            case_ioc_ids = case_data.get('ioc_ids', [])
            
            # Check if they share any IOCs
            shared_iocs = set(ioc_ids) & set(case_ioc_ids)
            if shared_iocs:
                if case_id not in node_ids:
                    nodes.append({
                        'data': {
                            'id': case_id,
                            'label': str(case_data.get('title', 'Unknown Case')),
                            'entity_type': 'case',
                            'status': case_data.get('status', 'unknown')
                        },
                        'classes': 'case'
                    })
                    node_ids.add(case_id)
                
                edge_id = f"{incident_id}-{case_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': incident_id,
                            'target': case_id,
                            'label': f'shares-{len(shared_iocs)}-iocs'
                        },
                        'classes': 'relation-shares_iocs'
                    })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch cases: {str(e)}")
    
    # Get other incidents that share IOCs with this incident
    try:
        all_incidents = case_service.es.search(
            'incidents',
            {'size': 1000, 'query': {'match_all': {}}}
        )
        
        for hit in all_incidents.get('hits', {}).get('hits', []):
            other_incident_id = hit.get('_id')
            if other_incident_id == incident_id:
                continue
            
            other_incident_data = hit.get('_source', {})
            other_ioc_ids = other_incident_data.get('ioc_ids', [])
            
            # Check if they share any IOCs
            shared_iocs = set(ioc_ids) & set(other_ioc_ids)
            if shared_iocs:
                if other_incident_id not in node_ids:
                    nodes.append({
                        'data': {
                            'id': other_incident_id,
                            'label': str(other_incident_data.get('title', 'Unknown Incident')),
                            'entity_type': 'incident',
                            'severity': other_incident_data.get('severity', 'unknown')
                        },
                        'classes': 'incident'
                    })
                    node_ids.add(other_incident_id)
                
                edge_id = f"{incident_id}-{other_incident_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': incident_id,
                            'target': other_incident_id,
                            'label': f'shares-{len(shared_iocs)}-iocs'
                        },
                        'classes': 'relation-shares_iocs'
                    })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch incidents: {str(e)}")
    
    # Always return nodes and edges, at least with the incident node
    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'count': len(nodes)
    })


@bp.route('/api/cases/<case_id>/generate-report', methods=['POST'])
@login_required
@permission_required('report.create')
def api_generate_case_report(case_id):
    """Generate LLM report for case."""
    import os
    import uuid
    from datetime import datetime
    from app.services.elasticsearch_service import ElasticsearchService
    
    # Check if LLM is enabled
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_case_report as task_generate_case
        
        # Generate task ID upfront so we can create ES doc before launching task
        task_id = str(uuid.uuid4())
        
        # Create initial ES document so status check works immediately
        es_service = ElasticsearchService()
        es_service.index('elaslip_app_config', f'report_{task_id}', {
            'type': 'case',
            'entity_id': case_id,
            'status': 'queued',
            'user_id': current_user.username,
            'created_at': datetime.utcnow().isoformat(),
            'task_id': task_id
        })
        
        # Launch async task with our generated task_id
        task = task_generate_case.apply_async(
            args=[case_id, current_user.username],
            task_id=task_id
        )
        
        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'message': 'Report generation started'
        })
    except Exception as e:
        logger.exception("Error launching case report task: %s", e)
        return jsonify({'error': str(e)}), 500


@bp.route('/api/incidents/<incident_id>/generate-report', methods=['POST'])
@login_required
@permission_required('report.create')
def api_generate_incident_report(incident_id):
    """Generate LLM report for incident."""
    import os
    import uuid
    from datetime import datetime
    from app.services.elasticsearch_service import ElasticsearchService
    
    # Check if LLM is enabled
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_incident_report as task_generate_incident
        
        # Generate task ID upfront so we can create ES doc before launching task
        task_id = str(uuid.uuid4())
        
        # Create initial ES document so status check works immediately
        es_service = ElasticsearchService()
        es_service.index('elaslip_app_config', f'report_{task_id}', {
            'type': 'incident',
            'entity_id': incident_id,
            'status': 'queued',
            'user_id': current_user.username,
            'created_at': datetime.utcnow().isoformat(),
            'task_id': task_id
        })
        
        # Launch async task with our generated task_id
        task = task_generate_incident.apply_async(
            args=[incident_id, current_user.username],
            task_id=task_id
        )
        
        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'message': 'Report generation started'
        })
    except Exception as e:
        logger.exception("Error launching incident report task: %s", e)
        return jsonify({'error': str(e)}), 500
