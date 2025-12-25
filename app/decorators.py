"""Permission-based access control decorators and utilities."""

from functools import wraps
from flask import jsonify, request
from flask_login import current_user, login_required
from app.services.rbac_service import RBACService


def permission_required(*permissions, require_all=False):
    """
    Decorator to check if user has required permissions.
    Automatically includes login_required check.
    
    Args:
        *permissions: Permission strings to check (e.g., 'ioc.create', 'case.edit')
        require_all: If True, user must have ALL permissions. If False, ANY permission.
    
    Usage:
        @permission_required('ioc.create', 'ioc.edit')  # requires ANY
        @permission_required('ioc.create', require_all=True)  # requires ALL
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            if not current_user.is_authenticated:
                if request.is_json or request.headers.get('Accept') == 'application/json':
                    return jsonify({'error': 'Authentication required'}), 401
                else:
                    from flask import redirect, url_for
                    return redirect(url_for('auth.login'))
            
            rbac = RBACService()
            
            if require_all:
                has_perm = rbac.user_has_all_permissions(current_user, list(permissions))
            else:
                has_perm = rbac.user_has_any_permission(current_user, list(permissions))
            
            if not has_perm:
                if request.is_json or request.headers.get('Accept') == 'application/json':
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'required_permissions': list(permissions),
                        'require_all': require_all
                    }), 403
                else:
                    # Redirect to forbidden page or settings
                    from flask import render_template
                    return render_template('error.html', 
                                         error='Insufficient permissions',
                                         status=403), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_user_permissions():
    """Get current user's permissions."""
    rbac = RBACService()
    return rbac.get_user_permissions(current_user)


def check_permission(permission):
    """Check if current user has a specific permission."""
    rbac = RBACService()
    return rbac.user_has_permission(current_user, permission)


def check_any_permission(*permissions):
    """Check if current user has any of the given permissions."""
    rbac = RBACService()
    return rbac.user_has_any_permission(current_user, list(permissions))


def check_all_permissions(*permissions):
    """Check if current user has all of the given permissions."""
    rbac = RBACService()
    return rbac.user_has_all_permissions(current_user, list(permissions))
