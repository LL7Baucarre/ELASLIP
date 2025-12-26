"""Checklist Template Routes."""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user

from app.decorators import permission_required
from app.services.checklist_template_service import ChecklistTemplateService

bp = Blueprint('checklist_templates', __name__, url_prefix='/checklist-templates')

template_service = ChecklistTemplateService()


# ============== Web Routes ==============

@bp.route('/')
@login_required
@permission_required('checklist.template.view')
def list_page():
    """List checklist templates page."""
    page = request.args.get('page', 1, type=int)
    
    result = template_service.list_templates(page=page, created_by=None, include_public=True)
    return render_template('checklist_templates/list.html', templates=result['items'], 
                         total=result['total'], page=page, pages=result['pages'])


@bp.route('/new')
@login_required
@permission_required('checklist.template.create')
def new_page():
    """Create new template page."""
    return render_template('checklist_templates/new.html')


@bp.route('/<template_id>')
@login_required
@permission_required('checklist.template.view')
def detail_page(template_id):
    """Template detail page."""
    template = template_service.get_template(template_id)
    if not template:
        flash('Template not found', 'error')
        return redirect(url_for('checklist_templates.list_page'))
    
    # Check if user has permission to edit (owner or admin)
    can_edit = (current_user.is_admin or template['created_by'] == current_user.username) and \
               current_user.has_permission('checklist.template.edit')
    
    return render_template('checklist_templates/detail.html', template=template, can_edit=can_edit)


# ============== API Routes ==============

@bp.route('/api/create', methods=['POST'])
@login_required
@permission_required('checklist.template.create')
def api_create():
    """Create a new template via API."""
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    is_public = data.get('is_public', False)
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    template = template_service.create_template(
        name=name,
        description=description,
        created_by=current_user.username,
        is_public=is_public
    )
    
    return jsonify(template), 201


@bp.route('/api/<template_id>/update', methods=['PUT'])
@login_required
@permission_required('checklist.template.edit')
def api_update(template_id):
    """Update a template."""
    data = request.get_json()
    template = template_service.get_template(template_id)
    
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    # Check ownership
    if not (current_user.is_admin or template['created_by'] == current_user.username):
        return jsonify({'error': 'Unauthorized'}), 403
    
    updates = {}
    if 'name' in data:
        updates['name'] = data['name'].strip()
    if 'description' in data:
        updates['description'] = data['description'].strip()
    if 'is_public' in data:
        updates['is_public'] = data['is_public']
    
    template = template_service.update_template(template_id, updates)
    if not template:
        return jsonify({'error': 'Failed to update template'}), 500
    
    return jsonify(template)


@bp.route('/api/<template_id>/delete', methods=['DELETE'])
@login_required
@permission_required('checklist.template.delete')
def api_delete(template_id):
    """Delete a template."""
    template = template_service.get_template(template_id)
    
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    # Check ownership
    if not (current_user.is_admin or template['created_by'] == current_user.username):
        return jsonify({'error': 'Unauthorized'}), 403
    
    if not template_service.delete_template(template_id):
        return jsonify({'error': 'Failed to delete template'}), 500
    
    return jsonify({'success': True})


@bp.route('/api/<template_id>/add-item', methods=['POST'])
@login_required
@permission_required('checklist.template.edit')
def api_add_item(template_id):
    """Add an item to a template."""
    data = request.get_json()
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    
    if not title:
        return jsonify({'error': 'Item title is required'}), 400
    
    template = template_service.get_template(template_id)
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    # Check ownership
    if not (current_user.is_admin or template['created_by'] == current_user.username):
        return jsonify({'error': 'Unauthorized'}), 403
    
    template = template_service.add_item(template_id, title, description)
    if not template:
        return jsonify({'error': 'Failed to add item'}), 500
    
    return jsonify(template)


@bp.route('/api/<template_id>/items/<item_id>/delete', methods=['DELETE'])
@login_required
@permission_required('checklist.template.edit')
def api_delete_item(template_id, item_id):
    """Delete an item from a template."""
    template = template_service.get_template(template_id)
    
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    # Check ownership
    if not (current_user.is_admin or template['created_by'] == current_user.username):
        return jsonify({'error': 'Unauthorized'}), 403
    
    template = template_service.delete_item(template_id, item_id)
    if not template:
        return jsonify({'error': 'Failed to delete item'}), 500
    
    return jsonify(template)


@bp.route('/api/<template_id>/use', methods=['GET'])
@login_required
@permission_required('checklist.template.use')
def api_use_template(template_id):
    """Get template data for creating a new checklist."""
    template_data = template_service.use_template(template_id)
    
    if not template_data:
        return jsonify({'error': 'Template not found'}), 404
    
    return jsonify(template_data)
