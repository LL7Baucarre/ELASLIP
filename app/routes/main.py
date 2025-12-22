"""Main routes for web interface."""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
import os
from dotenv import load_dotenv, set_key

from app.services.ioc_service import IOCService
from app.auth import User

main_bp = Blueprint('main', __name__)


def admin_required(f):
    """Decorator to require admin privileges."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin privileges required', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@main_bp.route('/')
def index():
    """Landing page."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with IOC statistics."""
    service = IOCService()
    stats = service.get_stats()
    
    # Get recent IOCs
    recent = service.list(page=1, per_page=10)
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          recent_iocs=recent['items'])


@main_bp.route('/iocs')
@login_required
def iocs_list():
    """IOC listing page."""
    return render_template('iocs/list.html')


@main_bp.route('/iocs/add')
@login_required
def iocs_add():
    """Add IOC page."""
    return render_template('iocs/add.html')


@main_bp.route('/iocs/<ioc_id>')
@login_required
def iocs_detail(ioc_id):
    """IOC detail page."""
    service = IOCService()
    ioc = service.get(ioc_id)
    
    if not ioc:
        return render_template('errors/404.html'), 404
    
    return render_template('iocs/detail.html', ioc=ioc)


@main_bp.route('/search')
@login_required
def search_page():
    """Search page."""
    return render_template('search.html')


@main_bp.route('/import')
@login_required
def import_page():
    """Import page."""
    return render_template('import.html')


@main_bp.route('/tools')
@login_required
def tools_page():
    """Tools page for WHOIS and Nmap scans."""
    return render_template('tools.html')


@main_bp.route('/settings')
@login_required
def settings():
    """Settings page."""
    return render_template('settings/index.html')


@main_bp.route('/api/settings', methods=['GET', 'PUT'])
@login_required
@admin_required
def api_settings():
    """Get or update site settings (admin only)."""
    if request.method == 'GET':
        return jsonify({
            'site_name': current_app.config.get('SITE_NAME', 'IOC Manager'),
            'site_title': current_app.config.get('SITE_TITLE', 'IOC Manager')
        })
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    site_name = data.get('site_name', '').strip()
    site_title = data.get('site_title', '').strip()
    
    if not site_name or not site_title:
        return jsonify({'error': 'site_name and site_title are required'}), 400
    
    # Update .env file
    env_file = '.env'
    if os.path.exists(env_file):
        set_key(env_file, 'SITE_NAME', site_name)
        set_key(env_file, 'SITE_TITLE', site_title)
    
    # Update current app config
    current_app.config['SITE_NAME'] = site_name
    current_app.config['SITE_TITLE'] = site_title
    
    return jsonify({
        'message': 'Settings updated successfully',
        'site_name': site_name,
        'site_title': site_title
    })


@main_bp.route('/settings/api-keys')
@login_required
def settings_api_keys():
    """API Keys settings page."""
    return render_template('settings/api_keys.html')


@main_bp.route('/settings/external-apis')
@login_required
def settings_external_apis():
    """External APIs settings page."""
    return render_template('settings/external_apis.html')


@main_bp.route('/settings/webhooks')
@login_required
def settings_webhooks():
    """Webhooks settings page."""
    return render_template('settings/webhooks.html')

@main_bp.route('/api-docs')
@login_required
def api_docs():
    """API documentation page."""
    return render_template('api_docs.html')


@main_bp.route('/admin/users')
@login_required
@admin_required
def users_management():
    """User management page (admin only)."""
    users = User.get_all()
    return render_template('admin/users.html', users=users)


@main_bp.route('/admin/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Create a new user (admin only)."""
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    is_admin = data.get('is_admin', False)
    
    if not all([username, email, password]):
        if request.is_json:
            return jsonify({'error': 'All fields required'}), 400
        flash('All fields required', 'error')
        return redirect(url_for('main.users_management'))
    
    if len(password) < 8:
        if request.is_json:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('main.users_management'))
    
    # Convert to boolean if it's a string
    if isinstance(is_admin, str):
        is_admin = is_admin.lower() in ['true', '1', 'yes', 'on']
    
    user, error = User.create(username, email, password, is_admin=is_admin)
    
    if error:
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('main.users_management'))
    
    if request.is_json:
        return jsonify({'message': 'User created successfully', 'user': user.to_dict()}), 201
    
    flash(f'User {username} created successfully', 'success')
    return redirect(url_for('main.users_management'))


@main_bp.route('/admin/users/<user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit user (admin only)."""
    user = User.get_by_id(user_id)
    if not user:
        if request.is_json:
            return jsonify({'error': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('main.users_management'))
    
    # Try to get JSON data, force parse if needed
    data = {}
    try:
        if request.is_json or request.content_type == 'application/json':
            data = request.get_json(force=True) or {}
        else:
            data = request.form.to_dict()
    except:
        data = request.form.to_dict()
    
    # Prevent editing own admin status
    if user_id == current_user.id and 'is_admin' in data:
        if data.get('is_admin') == False:
            if request.is_json:
                return jsonify({'error': 'Cannot remove your own admin status'}), 400
            flash('Cannot remove your own admin status', 'error')
            return redirect(url_for('main.users_management'))
    
    update_data = {}
    if 'email' in data:
        update_data['email'] = data.get('email', '').strip()
    if 'is_admin' in data:
        is_admin = data.get('is_admin')
        if isinstance(is_admin, str):
            is_admin = is_admin.lower() in ['true', '1', 'yes', 'on']
        update_data['is_admin'] = is_admin
    if 'password' in data:
        password = data.get('password', '').strip()
        if password:
            if len(password) < 8:
                if request.is_json:
                    return jsonify({'error': 'Password must be at least 8 characters'}), 400
                flash('Password must be at least 8 characters', 'error')
                return redirect(url_for('main.users_management'))
            update_data['password'] = password
    
    user.update(**update_data)
    
    if request.is_json:
        return jsonify({'message': 'User updated successfully', 'user': user.to_dict()})
    
    flash(f'User {user.username} updated successfully', 'success')
    return redirect(url_for('main.users_management'))


@main_bp.route('/admin/users/<user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete user (admin only)."""
    if user_id == current_user.id:
        if request.is_json:
            return jsonify({'error': 'Cannot delete yourself'}), 400
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('main.users_management'))
    
    user = User.get_by_id(user_id)
    if not user:
        if request.is_json:
            return jsonify({'error': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('main.users_management'))
    
    username = user.username
    user.delete()
    
    if request.is_json:
        return jsonify({'message': 'User deleted successfully'})
    
    flash(f'User {username} deleted successfully', 'success')
    return redirect(url_for('main.users_management'))