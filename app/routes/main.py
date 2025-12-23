"""Main routes for web interface."""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
import os
from dotenv import load_dotenv, set_key

from app.services.ioc_service import IOCService
from app.auth import User

main_bp = Blueprint('main', __name__)


def make_ioc_template_friendly(ioc):
    """
    Add convenience properties to STIX 2.1 IOC for template access.
    
    This adds convenience accessors at the root level for template compatibility
    while keeping the actual IOC storage STIX 2.1 compliant.
    
    The original data is in x_metadata, but templates can access via ioc.ioc_type etc.
    """
    if not isinstance(ioc, dict):
        return ioc
    
    # Create a wrapper that provides both STIX structure and convenience access
    class IOCWrapper(dict):
        def __getattribute__(self, name):
            # Avoid infinite recursion with internal methods
            if name.startswith('_') or name in ('get', 'keys', 'values', 'items', 'pop', 'update', 'clear'):
                return super().__getattribute__(name)
            
            # Try direct dict access first
            try:
                return dict.__getitem__(self, name)
            except KeyError:
                pass
            
            # Then try x_metadata for custom fields
            try:
                x_metadata = dict.__getitem__(self, 'x_metadata')
                if isinstance(x_metadata, dict) and name in x_metadata:
                    return x_metadata[name]
            except KeyError:
                pass
            
            # Finally, call parent __getattr__ for special methods
            return super().__getattribute__(name)
        
        def __getitem__(self, key):
            # Direct key access from dict
            try:
                return dict.__getitem__(self, key)
            except KeyError:
                pass
            
            # Try x_metadata for convenience fields (custom STIX properties)
            convenience_fields = {'ioc_type', 'ioc_value', 'threat_level', 'tlp', 'campaigns', 
                                'risk_score', 'status', 'created_by', 'asn', 'country'}
            if key in convenience_fields:
                try:
                    x_metadata = dict.__getitem__(self, 'x_metadata')
                    if isinstance(x_metadata, dict) and key in x_metadata:
                        return x_metadata[key]
                except KeyError:
                    pass
            
            raise KeyError(key)
        
        def get(self, key, default=None):
            try:
                return self[key]
            except KeyError:
                return default
    
    # Create wrapper from existing IOC dict
    wrapped = IOCWrapper(ioc)
    return wrapped


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
    
    # Make IOCs template-friendly
    template_iocs = [make_ioc_template_friendly(ioc) for ioc in recent['items']]
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          recent_iocs=template_iocs)


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
    
    # Make IOC template-friendly
    ioc = make_ioc_template_friendly(ioc)
    
    # Extract enrichment data for template display
    enrichment_data = None
    if isinstance(ioc, dict) and 'x_enrichment' in ioc:
        x_enrichment = ioc['x_enrichment']
        if isinstance(x_enrichment, dict):
            enrichment_data = {
                'enriched_at': x_enrichment.get('enriched_at'),
                'enriched_by': x_enrichment.get('enriched_by'),
                'api_results': x_enrichment.get('api_results', [])
            }
    
    return render_template('iocs/detail.html', ioc=ioc, enrichment_data=enrichment_data)


@main_bp.route('/iocs/graph')
@login_required
def iocs_graph():
    """IOC graph visualization page."""
    return render_template('iocs/graph.html')


@main_bp.route('/activity')
@login_required
def activity_timeline():
    """Activity timeline page."""
    return render_template('activity.html')


@main_bp.route('/api/iocs/graph-data')
@login_required
def get_graph_data():
    """Get IOCs and relationships for graph visualization."""
    service = IOCService()
    
    # Get all IOCs with limit
    limit = request.args.get('limit', default=100, type=int)
    all_iocs = service.list(page=1, per_page=limit)
    
    nodes = []
    edges = []
    node_ids = {}
    edge_set = set()
    
    # Create nodes from IOCs
    for ioc in all_iocs.get('items', []):
        node_id = ioc.get('id')
        node_ids[node_id] = ioc
        nodes.append({
            'data': {
                'id': node_id,
                'label': ioc.get('ioc_value', ioc.get('value', 'Unknown')),
                'type': ioc.get('ioc_type', ''),
                'threat_level': ioc.get('threat_level', 'unknown'),
                'confidence': ioc.get('confidence', ''),
                'tlp': ioc.get('tlp', '')
            },
            'classes': f"ioc-{ioc.get('ioc_type', 'unknown').replace('-', '_')}"
        })
    
    # Get relationships from Elasticsearch
    try:
        # First, try to get all relations from the index
        all_relations = service.es.search(
            'ioc_relations',
            {
                'size': 10000,
                'query': {'match_all': {}}
            }
        )
        
        total_relations = all_relations.get('hits', {}).get('total', {}).get('value', 0)
        current_app.logger.info(f"Total relations found in index: {total_relations}")
        
        # Log details of loaded IOCs
        current_app.logger.info(f"Loaded IOC IDs: {list(node_ids.keys())}")
        
        # Create edges from relationships
        for rel in all_relations.get('hits', {}).get('hits', []):
            rel_data = rel.get('_source', {})
            rel_id = rel.get('_id', '')
            
            # Try both naming conventions
            source_id = rel_data.get('source_id') or rel_data.get('ioc_id')
            target_id = rel_data.get('target_id') or rel_data.get('related_ioc_id')
            relation_type = rel_data.get('relation_type', 'related-to')
            
            current_app.logger.debug(f"Relation {rel_id}: {source_id} -> {target_id} ({relation_type})")
            current_app.logger.debug(f"Source in nodes: {source_id in node_ids}, Target in nodes: {target_id in node_ids}")
            
            # Only add edge if both nodes exist and edge not already added
            if source_id and target_id and source_id in node_ids and target_id in node_ids:
                edge_id = f"{source_id}-{target_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_id,
                            'target': target_id,
                            'label': relation_type
                        },
                        'classes': f"relation-{relation_type.replace('-', '_')}"
                    })
                    current_app.logger.info(f"Added edge: {edge_id}")
        
        current_app.logger.info(f"Final: {len(edges)} edges created for graph")
    except Exception as e:
        # Relations index might not exist, continue without relations
        import traceback
        current_app.logger.error(f"Could not fetch relations: {str(e)}")
        current_app.logger.error(traceback.format_exc())
    
    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'count': len(nodes),
        'relations_count': len(edges)
    })


@main_bp.route('/api/debug/relations')
@login_required
def debug_relations():
    """Debug endpoint to check relations in Elasticsearch."""
    service = IOCService()
    
    try:
        all_relations = service.es.search(
            'ioc_relations',
            {'size': 100, 'query': {'match_all': {}}}
        )
        
        relations_list = []
        for rel in all_relations.get('hits', {}).get('hits', []):
            relations_list.append({
                'id': rel.get('_id'),
                'data': rel.get('_source', {})
            })
        
        return jsonify({
            'total': all_relations.get('hits', {}).get('total', {}).get('value', 0),
            'relations': relations_list
        })
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        })


@main_bp.route('/api/iocs/<ioc_id>/graph-data')
@login_required
def get_ioc_graph_data(ioc_id):
    """Get graph data for a specific IOC and its relations."""
    service = IOCService()
    
    nodes = []
    edges = []
    edge_set = set()  # Track edges to avoid duplicates
    
    try:
        # Get the main IOC
        main_ioc = service.get(ioc_id)
        if not main_ioc:
            return jsonify({'error': 'IOC not found'}), 404
        
        # Add main IOC as central node
        nodes.append({
            'data': {
                'id': main_ioc['id'],
                'label': main_ioc.get('ioc_value', main_ioc.get('value', 'Unknown')),
                'type': main_ioc.get('ioc_type', ''),
                'threat_level': main_ioc.get('threat_level', 'unknown'),
                'confidence': main_ioc.get('confidence', ''),
                'tlp': main_ioc.get('tlp', '')
            },
            'classes': f"ioc-{main_ioc.get('ioc_type', 'unknown').replace('-', '_')}"
        })
        
        # Get all relations for this IOC
        all_relations = service.es.search(
            'ioc_relations',
            {'size': 10000, 'query': {'match_all': {}}}
        )
        
        related_ioc_ids = set()
        
        # Find relations where this IOC is source or target
        for rel in all_relations.get('hits', {}).get('hits', []):
            rel_data = rel.get('_source', {})
            source_id = rel_data.get('source_id') or rel_data.get('ioc_id')
            target_id = rel_data.get('target_id') or rel_data.get('related_ioc_id')
            relation_type = rel_data.get('relation_type', 'related-to')
            
            # Check if this IOC is involved in the relation
            if source_id == ioc_id and target_id:
                related_ioc_ids.add(target_id)
                edge_id = f"{source_id}-{target_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_id,
                            'target': target_id,
                            'label': relation_type
                        },
                        'classes': f"relation-{relation_type.replace('-', '_')}"
                    })
            elif target_id == ioc_id and source_id:
                related_ioc_ids.add(source_id)
                edge_id = f"{source_id}-{target_id}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_id,
                            'target': target_id,
                            'label': relation_type
                        },
                        'classes': f"relation-{relation_type.replace('-', '_')}"
                    })
        
        # Load related IOCs
        for related_id in related_ioc_ids:
            try:
                related_ioc = service.get(related_id)
                if related_ioc:
                    nodes.append({
                        'data': {
                            'id': related_ioc['id'],
                            'label': related_ioc.get('ioc_value', related_ioc.get('value', 'Unknown')),
                            'type': related_ioc.get('ioc_type', ''),
                            'threat_level': related_ioc.get('threat_level', 'unknown'),
                            'confidence': related_ioc.get('confidence', ''),
                            'tlp': related_ioc.get('tlp', '')
                        },
                        'classes': f"ioc-{related_ioc.get('ioc_type', 'unknown').replace('-', '_')}"
                    })
            except:
                pass
        
        return jsonify({
            'nodes': nodes,
            'edges': edges,
            'count': len(nodes)
        })
    except Exception as e:
        import traceback
        current_app.logger.error(f"Error getting IOC graph data: {str(e)}")
        return jsonify({
            'error': str(e),
            'nodes': [],
            'edges': []
        })

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


@main_bp.route('/settings/scheduled-tasks')
@login_required
@admin_required
def settings_scheduled_tasks():
    """Scheduled tasks settings page (admin only)."""
    return render_template('settings/scheduled_tasks.html')


@main_bp.route('/api/scheduled-tasks/run', methods=['POST'])
@login_required
@admin_required
def run_scheduled_task():
    """Run a scheduled task manually."""
    from app.tasks.expiration_tasks import (
        check_expired_iocs, check_expiring_soon, 
        cleanup_old_versions, update_risk_scores, cleanup_old_audit_logs
    )
    from app.services.elasticsearch_service import ElasticsearchService
    from datetime import datetime
    
    data = request.get_json()
    task_name = data.get('task')
    params = data.get('params', {})
    
    task_map = {
        'check_expired_iocs': check_expired_iocs,
        'check_expiring_soon': check_expiring_soon,
        'cleanup_old_versions': cleanup_old_versions,
        'update_risk_scores': update_risk_scores,
        'cleanup_old_audit_logs': cleanup_old_audit_logs
    }
    
    if task_name not in task_map:
        return jsonify({'error': f'Unknown task: {task_name}'}), 400
    
    # Log task execution start
    es = ElasticsearchService()
    execution_id = f"{task_name}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    try:
        es.index('task_executions', execution_id, {
            'task_name': task_name,
            'status': 'running',
            'started_at': datetime.utcnow().isoformat() + 'Z',
            'started_by': current_user.username,
            'params': params
        })
    except Exception:
        pass
    
    # Run task asynchronously
    try:
        if params:
            task_map[task_name].delay(**params)
        else:
            task_map[task_name].delay()
        
        return jsonify({
            'message': f'Task {task_name} started',
            'execution_id': execution_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/api/scheduled-tasks/history', methods=['GET'])
@login_required
@admin_required
def get_task_history():
    """Get recent task execution history."""
    from app.services.elasticsearch_service import ElasticsearchService
    
    es = ElasticsearchService()
    
    try:
        result = es.search('task_executions', {
            'query': {'match_all': {}},
            'sort': [{'started_at': {'order': 'desc'}}],
            'size': 50
        })
        
        executions = []
        for hit in result.get('hits', {}).get('hits', []):
            exec_data = hit['_source']
            exec_data['id'] = hit['_id']
            executions.append(exec_data)
        
        return jsonify({'executions': executions})
    except Exception:
        return jsonify({'executions': []})


@main_bp.route('/api/scheduled-tasks/config', methods=['GET', 'PUT'])
@login_required
@admin_required
def task_config():
    """Get or update task configuration."""
    from app.services.elasticsearch_service import ElasticsearchService
    
    es = ElasticsearchService()
    config_id = 'scheduled_tasks_config'
    
    if request.method == 'GET':
        try:
            result = es.get('app_config', config_id)
            return jsonify({'config': result})
        except Exception:
            return jsonify({'config': {
                'expiring_days': 7,
                'keep_versions': 50,
                'audit_retention': 90
            }})
    
    # PUT - update config
    data = request.get_json()
    config = {
        'expiring_days': data.get('expiring_days', 7),
        'keep_versions': data.get('keep_versions', 50),
        'audit_retention': data.get('audit_retention', 90),
        'updated_at': request.json.get('updated_at', None) or __import__('datetime').datetime.utcnow().isoformat() + 'Z',
        'updated_by': current_user.username
    }
    
    try:
        es.index('app_config', config_id, config)
        return jsonify({'message': 'Configuration saved', 'config': config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
    role = data.get('role', 'viewer').strip()
    
    # Validate role
    valid_roles = ['viewer', 'analyst', 'admin']
    if role not in valid_roles:
        if request.is_json:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
        flash(f'Invalid role. Must be one of: {", ".join(valid_roles)}', 'error')
        return redirect(url_for('main.users_management'))
    
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
    
    # Create user with role
    is_admin = role == 'admin'
    user, error = User.create(username, email, password, is_admin=is_admin, role=role)
    
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
    
    # Prevent editing own role status
    if user_id == current_user.id and 'role' in data:
        if data.get('role') != 'admin':
            if request.is_json:
                return jsonify({'error': 'Cannot remove your own admin role'}), 400
            flash('Cannot remove your own admin role', 'error')
            return redirect(url_for('main.users_management'))
    
    update_data = {}
    if 'email' in data:
        update_data['email'] = data.get('email', '').strip()
    
    # Handle role update
    if 'role' in data:
        role = data.get('role', '').strip()
        valid_roles = ['viewer', 'analyst', 'admin']
        if role not in valid_roles:
            if request.is_json:
                return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
            flash(f'Invalid role. Must be one of: {", ".join(valid_roles)}', 'error')
            return redirect(url_for('main.users_management'))
        update_data['role'] = role
        update_data['is_admin'] = (role == 'admin')
    
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


# =====================================
# CASES, INCIDENTS & SNIPPETS ROUTES
# =====================================

@main_bp.route('/cases')
@login_required
def cases_list():
    """Cases listing page."""
    return render_template('cases/list.html')


@main_bp.route('/cases/new')
@login_required
def cases_new():
    """Create new case page."""
    return render_template('cases/new.html')


@main_bp.route('/cases/<case_id>')
@login_required
def cases_detail(case_id):
    """Case detail page."""
    from app.services.case_service import CaseService
    service = CaseService()
    case = service.get_case(case_id)
    
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('main.cases_list'))
    
    return render_template('cases/detail.html', case=case)


@main_bp.route('/incidents')
@login_required
def incidents_list():
    """Incidents listing page."""
    return render_template('incidents/list.html')


@main_bp.route('/incidents/new')
@login_required
def incidents_new():
    """Create new incident page."""
    return render_template('incidents/new.html')


@main_bp.route('/incidents/<incident_id>')
@login_required
def incidents_detail(incident_id):
    """Incident detail page with report editor."""
    from app.services.case_service import IncidentService
    service = IncidentService()
    incident = service.get_incident(incident_id)
    
    if not incident:
        flash('Incident not found', 'error')
        return redirect(url_for('main.incidents_list'))
    
    return render_template('incidents/detail.html', incident=incident)


@main_bp.route('/snippets')
@login_required
def snippets_library():
    """Markdown snippets library page."""
    return render_template('snippets/library.html')