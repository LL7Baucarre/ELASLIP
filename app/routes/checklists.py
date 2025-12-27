"""Checklist Routes."""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user

from app.decorators import permission_required
from app.services.checklist_service import ChecklistService

bp = Blueprint('checklists', __name__, url_prefix='/checklists')

checklist_service = ChecklistService()


# ============== Web Routes ==============

@bp.route('/')
@login_required
@permission_required('checklist.view')
def list_page():
    """List checklists page."""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    
    result = checklist_service.list_checklists(page=page, status=status or None)
    return render_template('checklists/list.html', checklists=result['items'], 
                         total=result['total'], page=page, pages=result['pages'])


@bp.route('/new')
@login_required
@permission_required('checklist.create')
def new_page():
    """Create new checklist page."""
    return render_template('checklists/new.html')


@bp.route('/<checklist_id>')
@login_required
@permission_required('checklist.view')
def detail_page(checklist_id):
    """Checklist detail page."""
    checklist = checklist_service.get_checklist(checklist_id)
    if not checklist:
        flash('Checklist not found', 'error')
        return redirect(url_for('checklists.list_page'))
    
    return render_template('checklists/detail.html', checklist=checklist)


# ============== API Routes ==============

@bp.route('/api/create', methods=['POST'])
@login_required
@permission_required('checklist.create')
def api_create():
    """Create a new checklist via API."""
    data = request.get_json()
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    checklist = checklist_service.create_checklist(
        title=title,
        description=description,
        created_by=current_user.username,
        created_by_id=current_user.id,
        tags=data.get('tags', []),
        campaigns=data.get('campaigns', []),
        related_cases=data.get('related_cases', []),
        related_incidents=data.get('related_incidents', []),
        assigned_to=data.get('assigned_to', ''),
        assigned_to_name=data.get('assigned_to_name', '')
    )
    
    return jsonify(checklist), 201


@bp.route('/api/<checklist_id>/update', methods=['PUT'])
@login_required
@permission_required('checklist.edit')
def api_update(checklist_id):
    """Update a checklist."""
    data = request.get_json()
    
    updates = {}
    if 'title' in data:
        updates['title'] = data['title'].strip()
    if 'description' in data:
        updates['description'] = data['description'].strip()
    if 'status' in data:
        updates['status'] = data['status']
    if 'tags' in data:
        updates['tags'] = data['tags']
    if 'campaigns' in data:
        updates['campaigns'] = data['campaigns']
    if 'related_cases' in data:
        updates['related_cases'] = data['related_cases']
    if 'related_incidents' in data:
        updates['related_incidents'] = data['related_incidents']
    if 'assigned_to' in data:
        updates['assigned_to'] = data['assigned_to']
    if 'assigned_to_name' in data:
        updates['assigned_to_name'] = data['assigned_to_name']
    
    checklist = checklist_service.update_checklist(checklist_id, updates)
    if not checklist:
        return jsonify({'error': 'Checklist not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/delete', methods=['DELETE'])
@login_required
@permission_required('checklist.delete')
def api_delete(checklist_id):
    """Delete a checklist."""
    if not checklist_service.delete_checklist(checklist_id):
        return jsonify({'error': 'Checklist not found'}), 404
    
    return jsonify({'message': 'Checklist deleted'})


@bp.route('/api/<checklist_id>/add-item', methods=['POST'])
@login_required
@permission_required('checklist.edit')
def api_add_item(checklist_id):
    """Add an item to a checklist."""
    data = request.get_json()
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    checklist = checklist_service.add_item(checklist_id, title, description)
    if not checklist:
        return jsonify({'error': 'Checklist not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/items/<item_id>/toggle', methods=['PUT'])
@login_required
@permission_required('checklist.edit')
def api_toggle_item(checklist_id, item_id):
    """Toggle item completion."""
    checklist = checklist_service.toggle_item(checklist_id, item_id)
    if not checklist:
        return jsonify({'error': 'Item not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/items/<item_id>/update', methods=['PUT'])
@login_required
@permission_required('checklist.edit')
def api_update_item(checklist_id, item_id):
    """Update an item."""
    data = request.get_json()
    
    updates = {}
    if 'title' in data:
        updates['title'] = data['title'].strip()
    if 'description' in data:
        updates['description'] = data['description'].strip()
    
    checklist = checklist_service.update_item(checklist_id, item_id, updates)
    if not checklist:
        return jsonify({'error': 'Item not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/items/<item_id>/delete', methods=['DELETE'])
@login_required
@permission_required('checklist.edit')
def api_delete_item(checklist_id, item_id):
    """Delete an item from a checklist."""
    checklist = checklist_service.delete_item(checklist_id, item_id)
    if not checklist:
        return jsonify({'error': 'Item not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/items/<item_id>/comments', methods=['POST'])
@login_required
@permission_required('checklist.comment.create')
def api_add_comment(checklist_id, item_id):
    """Add a comment to a checklist item."""
    data = request.get_json()
    comment_text = data.get('text', '').strip()
    
    if not comment_text:
        return jsonify({'error': 'Comment text is required'}), 400
    
    checklist = checklist_service.add_comment_to_item(checklist_id, item_id, comment_text, 
                                                      current_user.username)
    if not checklist:
        return jsonify({'error': 'Item not found'}), 404
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/items/<item_id>/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_comment(checklist_id, item_id, comment_id):
    """Delete a comment from a checklist item."""
    # Get the checklist to find the comment
    checklist = checklist_service.get_checklist(checklist_id)
    if not checklist:
        return jsonify({'error': 'Checklist not found'}), 404
    
    # Find the comment to check ownership
    comment = None
    for item in checklist['items']:
        if item['id'] == item_id and 'comments' in item:
            for c in item['comments']:
                if c['id'] == comment_id:
                    comment = c
                    break
    
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    
    # Check permission: user must have delete_any or own the comment
    if not (current_user.has_permission('checklist.comment.delete_any') or 
            current_user.username == comment['user']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    checklist = checklist_service.delete_comment_from_item(checklist_id, item_id, comment_id)
    if not checklist:
        return jsonify({'error': 'Failed to delete comment'}), 500
    
    return jsonify(checklist)


@bp.route('/api/<checklist_id>/export', methods=['GET'])
@login_required
@permission_required('checklist.export')
def api_export(checklist_id):
    """Export checklist as Markdown."""
    markdown = checklist_service.export_markdown(checklist_id)
    if not markdown:
        return jsonify({'error': 'Checklist not found'}), 404
    
    return markdown, 200, {'Content-Type': 'text/markdown; charset=utf-8'}


@bp.route('/api/<checklist_id>/generate-report', methods=['POST'])
@login_required
@permission_required('checklist.generate_llm')
def api_generate_report(checklist_id):
    """Generate LLM report for checklist."""
    import os
    
    # Check if LLM is enabled
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_checklist_report as task_generate_checklist
        # Launch async task
        task = task_generate_checklist.delay(checklist_id, current_user.username)
        return jsonify({
            'task_id': task.id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

