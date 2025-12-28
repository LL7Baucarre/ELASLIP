"""RBAC Management Routes - for granular role and permission management."""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from app.auth import login_or_api_key_required
from app.decorators import permission_required
from app.services.rbac_service import RBACService
from app.rbac_matrix import get_permission_matrix, get_categories

rbac_bp = Blueprint('rbac', __name__)


@rbac_bp.route('/permissions', methods=['GET'])
@login_or_api_key_required
def list_permissions():
    """
    Get all available permissions grouped by category.
    
    Returns:
        JSON with permissions organized by category
    """
    from app.services.rbac_service import PERMISSIONS
    
    # Group permissions by category
    categories = {}
    for perm, desc in PERMISSIONS.items():
        category = perm.split('.')[0].title()
        if category not in categories:
            categories[category] = {}
        categories[category][perm] = desc
    
    return jsonify({
        'permissions': PERMISSIONS,
        'categories': categories,
        'total': len(PERMISSIONS)
    })


@rbac_bp.route('/roles', methods=['GET'])
@login_or_api_key_required
def list_roles():
    """
    Get all available roles with their permissions.
    
    Returns:
        JSON with all roles and their permission sets
    """
    rbac = RBACService()
    
    result = rbac.es.search('roles', {
        'query': {'match_all': {}},
        'size': 100
    })
    
    roles = []
    for hit in result['hits']['hits']:
        role = hit['_source']
        role['id'] = hit['_id']
        roles.append(role)
    
    return jsonify({
        'roles': roles,
        'total': len(roles)
    })


@rbac_bp.route('/roles/<role_name>', methods=['GET'])
@login_or_api_key_required
def get_role(role_name):
    """
    Get a specific role with its permissions.
    
    Args:
        role_name: Name of the role
    
    Returns:
        JSON with role details and permissions
    """
    rbac = RBACService()
    role = rbac.get_role(role_name)
    
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    return jsonify(role)


@rbac_bp.route('/roles', methods=['POST'])
@login_required
@permission_required('admin.roles.create')
def create_role():
    """
    Create a new custom role.
    
    Required permissions: admin.roles.create
    
    Request body:
    {
        "name": "custom_role",
        "display_name": "Custom Role",
        "description": "Description of the role",
        "permissions": ["ioc.view", "ioc.create", "case.view"]
    }
    """
    rbac = RBACService()
    
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    required_fields = ['name', 'display_name', 'permissions']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    # Validate permissions exist
    from app.services.rbac_service import PERMISSIONS
    invalid_perms = [p for p in data['permissions'] if p not in PERMISSIONS]
    if invalid_perms:
        return jsonify({
            'error': f'Invalid permissions: {invalid_perms}',
            'available_permissions': list(PERMISSIONS.keys())
        }), 400
    
    # Check if role already exists (and is not system role)
    existing_role = rbac.get_role(data['name'])
    if existing_role:
        if existing_role.get('is_system'):
            return jsonify({'error': 'Cannot modify system roles'}), 400
        else:
            return jsonify({'error': 'Role already exists'}), 400
    
    # Create the role
    role = rbac.create_role(
        name=data['name'],
        display_name=data['display_name'],
        description=data.get('description', ''),
        permissions=data['permissions'],
        is_system=False
    )
    
    return jsonify({
        'message': 'Role created successfully',
        'role': role
    }), 201


@rbac_bp.route('/roles/<role_name>', methods=['PUT'])
@login_required
@permission_required('admin.roles.edit')
def update_role(role_name):
    """
    Update a custom role (cannot modify system roles).
    
    Required permissions: admin.roles.edit
    """
    rbac = RBACService()
    
    role = rbac.get_role(role_name)
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    if role.get('is_system'):
        return jsonify({'error': 'Cannot modify system roles'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Validate permissions if provided
    if 'permissions' in data:
        from app.services.rbac_service import PERMISSIONS
        invalid_perms = [p for p in data['permissions'] if p not in PERMISSIONS]
        if invalid_perms:
            return jsonify({
                'error': f'Invalid permissions: {invalid_perms}'
            }), 400
    
    # Update role
    updates = {}
    for key in ['display_name', 'description', 'permissions']:
        if key in data:
            updates[key] = data[key]
    
    if updates:
        updates['updated_at'] = __import__('datetime').datetime.utcnow().isoformat() + 'Z'
        rbac.es.update('roles', role_name, {'doc': updates})
    
    updated_role = rbac.get_role(role_name)
    return jsonify({
        'message': 'Role updated successfully',
        'role': updated_role
    })


@rbac_bp.route('/roles/<role_name>', methods=['DELETE'])
@login_required
@permission_required('admin.roles.delete')
def delete_role(role_name):
    """
    Delete a custom role (cannot delete system roles).
    
    Required permissions: admin.roles.delete
    """
    rbac = RBACService()
    
    role = rbac.get_role(role_name)
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    if role.get('is_system'):
        return jsonify({'error': 'Cannot delete system roles'}), 400
    
    # Check if any users have this role
    # This is optional - you could allow deletion or cascade
    rbac.es.delete('roles', role_name)
    
    return jsonify({'message': 'Role deleted successfully'})


@rbac_bp.route('/permission-matrix', methods=['GET'])
@login_or_api_key_required
def get_permission_matrix_view():
    """
    Get the complete permission matrix showing which permissions apply to which roles.
    
    Returns:
        JSON with role-to-permission mapping and category organization
    """
    matrix = get_permission_matrix()
    categories = get_categories()
    
    return jsonify({
        'matrix': matrix,
        'categories': categories,
        'description': 'Permission matrix showing feature access by role'
    })


@rbac_bp.route('/user-permissions', methods=['GET'])
@login_required
def get_user_permissions():
    """
    Get the current user's permissions based on their role.
    
    Returns:
        JSON with user's permissions and role information
    """
    rbac = RBACService()
    permissions = rbac.get_user_permissions(current_user)
    
    # Group permissions by category
    categories = {}
    for perm in permissions:
        category = perm.split('.')[0].title()
        if category not in categories:
            categories[category] = []
        categories[category].append(perm)
    
    return jsonify({
        'user_id': current_user.id,
        'username': current_user.username,
        'role': getattr(current_user, 'role', 'viewer'),
        'is_admin': getattr(current_user, 'is_admin', False),
        'permissions': permissions,
        'permissions_by_category': categories,
        'total_permissions': len(permissions)
    })


@rbac_bp.route('/check-permission', methods=['POST'])
@login_required
def check_permission():
    """
    Check if the current user has specific permissions.
    
    Request body:
    {
        "permissions": ["ioc.view", "ioc.create"],
        "require_all": false  # true: user must have ALL permissions, false: ANY
    }
    
    Returns:
        JSON with permission check results
    """
    rbac = RBACService()
    data = request.get_json()
    
    if not data or 'permissions' not in data:
        return jsonify({'error': 'permissions array required'}), 400
    
    permissions = data['permissions']
    require_all = data.get('require_all', False)
    
    if require_all:
        has_permission = rbac.user_has_all_permissions(current_user, permissions)
    else:
        has_permission = rbac.user_has_any_permission(current_user, permissions)
    
    return jsonify({
        'has_permission': has_permission,
        'checked_permissions': permissions,
        'require_all': require_all
    })
