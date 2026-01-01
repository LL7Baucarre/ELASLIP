"""Main routes for web interface."""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
import os
from dotenv import load_dotenv, set_key

from app.services.ioc_service import IOCService
from app.services.case_service import CaseService
from app.services.checklist_service import ChecklistService
from app.services.rbac_service import RBACService, DEFAULT_ROLES
from app.services.backup_service import BackupService
from app.auth import User
from app.decorators import permission_required
from app.utils.request_helpers import transform_ioc_to_stix_compliant
import logging
logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)


def get_all_valid_roles():
    """Get all valid roles (default + custom)."""
    rbac = RBACService()
    # Start with default roles
    roles = list(DEFAULT_ROLES.keys())
    # Add custom roles from database
    try:
        custom_roles = rbac.get_all_roles()
        for role in custom_roles:
            if not role.get('is_system') and role['name'] not in roles:
                roles.append(role['name'])
    except Exception:
        pass  # If database is not ready, just use default roles
    return roles


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
    
    # Redirect to public search portal if enabled, otherwise to login
    if current_app.config.get('PUBLIC_SEARCH_ENABLED', False):
        return redirect(url_for('public_submissions.public_submission_page'))
    
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with statistics."""
    ioc_service = IOCService()
    case_service = CaseService()
    checklist_service = ChecklistService()
    es = ioc_service.es
    
    # Get IOC stats
    ioc_stats = ioc_service.get_stats()
    
    # Get entity counts
    try:
        total_iocs = es.count('ioc')
    except:
        total_iocs = 0
    
    try:
        cases_result = es.search('cases', {'size': 0})
        total_cases = cases_result['hits']['total']['value']
    except:
        total_cases = 0
    
    try:
        incidents_result = es.search('incidents', {'size': 0})
        total_incidents = incidents_result['hits']['total']['value']
    except:
        total_incidents = 0
    
    try:
        checklists_result = es.search('checklists', {'size': 0})
        total_checklists = checklists_result['hits']['total']['value']
    except:
        total_checklists = 0
    
    # Get stats by status/severity
    try:
        cases_by_status = es.aggregate('cases', {
            'by_status': {'terms': {'field': 'status.keyword', 'size': 10}}
        })
        cases_status_stats = {b['key']: b['doc_count'] 
                             for b in cases_by_status.get('aggregations', {}).get('by_status', {}).get('buckets', [])}
    except:
        cases_status_stats = {}
    
    try:
        incidents_by_severity = es.aggregate('incidents', {
            'by_severity': {'terms': {'field': 'severity.keyword', 'size': 10}}
        })
        incidents_severity_stats = {b['key']: b['doc_count'] 
                                   for b in incidents_by_severity.get('aggregations', {}).get('by_severity', {}).get('buckets', [])}
    except:
        incidents_severity_stats = {}
    
    try:
        iocs_by_threat = es.aggregate('ioc', {
            'by_threat_level': {'terms': {'field': 'x_metadata.threat_level.keyword', 'size': 10}}
        })
        iocs_threat_stats = {b['key']: b['doc_count'] 
                            for b in iocs_by_threat.get('aggregations', {}).get('by_threat_level', {}).get('buckets', [])}
    except:
        iocs_threat_stats = {}
    
    # Get recent IOCs
    try:
        recent = ioc_service.list(page=1, per_page=5)
        logger.debug("recent dict keys: %s", recent.keys())
        logger.debug("recent total: %s", recent.get('total'))
        logger.debug("recent items count: %d", len(recent.get('items', [])))
        template_iocs = [make_ioc_template_friendly(ioc) for ioc in recent.get('items', [])]
    except Exception as e:
        logger.exception("Error fetching recent IOCs: %s", e)
        template_iocs = []
    
    # Get recent cases
    try:
        recent_cases_result = es.search('cases', {
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_cases = [{'id': hit['_id'], 'entity_type': 'case', **hit['_source']} 
                       for hit in recent_cases_result['hits']['hits']]
    except:
        recent_cases = []
    
    # Get recent incidents
    try:
        recent_incidents_result = es.search('incidents', {
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_incidents = [{'id': hit['_id'], 'entity_type': 'incident', **hit['_source']} 
                           for hit in recent_incidents_result['hits']['hits']]
    except:
        recent_incidents = []
    
    # Get recent checklists
    try:
        recent_checklists_result = es.search('checklists', {
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_checklists = [{'id': hit['_id'], 'entity_type': 'checklist', **hit['_source']} 
                            for hit in recent_checklists_result['hits']['hits']]
    except:
        recent_checklists = []
    
    # Combine and sort recent entries
    all_recent = []
    for ioc in template_iocs:
        # For IOCs, try to get name from different possible locations
        ioc_name = None
        if isinstance(ioc, dict):
            # Try x_metadata.ioc_value first
            if 'x_metadata' in ioc and isinstance(ioc['x_metadata'], dict):
                ioc_name = ioc['x_metadata'].get('ioc_value')
            # Fallback to direct fields
            if not ioc_name:
                ioc_name = ioc.get('ioc_value')
            # Final fallback to pattern
            if not ioc_name:
                ioc_name = ioc.get('pattern', '')
        
        entry = {
            'id': ioc.get('id'),
            'entity_type': 'ioc',
            'name': ioc_name or 'Unknown',
            'ioc_type': ioc.get('ioc_type', 'unknown'),
            'updated_at': ioc.get('modified', ioc.get('created', ''))
        }
        import sys
        all_recent.append(entry)
    for case in recent_cases:
        all_recent.append({
            'id': case.get('id'),
            'entity_type': 'case',
            'name': case.get('title', 'Untitled'),
            'status': case.get('status', ''),
            'updated_at': case.get('updated_at', '')
        })
    for incident in recent_incidents:
        all_recent.append({
            'id': incident.get('id'),
            'entity_type': 'incident',
            'name': incident.get('title', 'Unnamed'),
            'severity': incident.get('severity', ''),
            'updated_at': incident.get('updated_at', '')
        })
    for checklist in recent_checklists:
        all_recent.append({
            'id': checklist.get('id'),
            'entity_type': 'checklist',
            'name': checklist.get('title', 'Unnamed'),
            'status': checklist.get('status', ''),
            'updated_at': checklist.get('updated_at', '')
        })
    
    # Sort by updated_at descending and take top 10
    all_recent = sorted(all_recent, key=lambda x: x.get('updated_at', ''), reverse=True)[:10]
    
    return render_template('dashboard.html', 
                          stats=ioc_stats,
                          total_iocs=total_iocs,
                          total_cases=total_cases,
                          total_incidents=total_incidents,
                          total_checklists=total_checklists,
                          cases_status_stats=cases_status_stats,
                          incidents_severity_stats=incidents_severity_stats,
                          iocs_threat_stats=iocs_threat_stats,
                          all_recent=all_recent)


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
    
    # Make IOC template-friendly for HTML access
    ioc_template = make_ioc_template_friendly(ioc)
    
    # Transform to STIX 2.1 compliant format for JSON display only
    stix_json_display = transform_ioc_to_stix_compliant(ioc)
    
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
    
    # Pass both versions: ioc_template for HTML rendering, stix_json_display for the JSON view
    return render_template('iocs/detail.html', ioc=ioc_template, stix_json_display=stix_json_display, enrichment_data=enrichment_data)


@main_bp.route('/iocs/graph')
@login_required
def iocs_graph():
    """IOC graph visualization page."""
    return render_template('iocs/graph.html')


@main_bp.route('/activity')
@login_required
@permission_required('admin.audit')
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
        
        # Build classes with IOC type and threat level
        ioc_type = ioc.get('ioc_type', 'unknown').replace('-', '_')
        threat_level = ioc.get('threat_level', 'unknown')
        classes = f"ioc-{ioc_type} threat-{threat_level}"
        
        nodes.append({
            'data': {
                'id': node_id,
                'label': ioc.get('ioc_value', ioc.get('value', 'Unknown')),
                'type': ioc.get('ioc_type', ''),
                'threat_level': threat_level,
                'confidence': ioc.get('confidence', ''),
                'tlp': ioc.get('tlp', '')
            },
            'classes': classes
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
@permission_required('tools.execute', 'tools.view', require_all=False)
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


@main_bp.route('/api/settings/public-submissions', methods=['GET', 'PUT'])
@login_required
@admin_required
def api_settings_public_submissions():
    """Get or update public submissions settings (admin only)."""
    if request.method == 'GET':
        return jsonify({
            'public_search_enabled': current_app.config.get('PUBLIC_SEARCH_ENABLED', True),
            'public_submissions_submit_enabled': current_app.config.get('PUBLIC_SUBMISSIONS_SUBMIT_ENABLED', True),
            'public_submissions_allow_anonymous': current_app.config.get('PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS', True),
            'public_submissions_max_results': current_app.config.get('PUBLIC_SUBMISSIONS_MAX_RESULTS', 50)
        })
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Convert values to appropriate types
    public_search_enabled = data.get('public_search_enabled', True)
    public_submissions_submit_enabled = data.get('public_submissions_submit_enabled', True)
    public_submissions_allow_anonymous = data.get('public_submissions_allow_anonymous', True)
    public_submissions_max_results = data.get('public_submissions_max_results', 50)
    
    # Validate max results
    try:
        public_submissions_max_results = int(public_submissions_max_results)
        if public_submissions_max_results < 1 or public_submissions_max_results > 1000:
            return jsonify({'error': 'public_submissions_max_results must be between 1 and 1000'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'public_submissions_max_results must be an integer'}), 400
    
    # Update .env file
    env_file = '.env'
    if os.path.exists(env_file):
        set_key(env_file, 'PUBLIC_SEARCH_ENABLED', str(public_search_enabled).lower())
        set_key(env_file, 'PUBLIC_SUBMISSIONS_SUBMIT_ENABLED', str(public_submissions_submit_enabled).lower())
        set_key(env_file, 'PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS', str(public_submissions_allow_anonymous).lower())
        set_key(env_file, 'PUBLIC_SUBMISSIONS_MAX_RESULTS', str(public_submissions_max_results))
    
    # Update current app config
    current_app.config['PUBLIC_SEARCH_ENABLED'] = public_search_enabled
    current_app.config['PUBLIC_SUBMISSIONS_SUBMIT_ENABLED'] = public_submissions_submit_enabled
    current_app.config['PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS'] = public_submissions_allow_anonymous
    current_app.config['PUBLIC_SUBMISSIONS_MAX_RESULTS'] = public_submissions_max_results
    
    return jsonify({
        'message': 'Public submissions settings updated successfully',
        'public_search_enabled': public_search_enabled,
        'public_submissions_submit_enabled': public_submissions_submit_enabled,
        'public_submissions_allow_anonymous': public_submissions_allow_anonymous,
        'public_submissions_max_results': public_submissions_max_results
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


@main_bp.route('/settings/roles')
@login_required
@admin_required
def settings_roles():
    """Roles and permissions management page (admin only)."""
    return render_template('settings/roles.html')


@main_bp.route('/settings/scheduled-tasks')
@login_required
@admin_required
def settings_scheduled_tasks():
    """Scheduled tasks settings page (admin only)."""
    return render_template('settings/scheduled_tasks.html')


@main_bp.route('/settings/llm')
@login_required
@admin_required
def settings_llm():
    """LLM report settings page (admin only)."""
    from app.config import Config
    return render_template('settings/llm.html', config=Config)


@main_bp.route('/settings/backup')
@login_required
@admin_required
def settings_backup():
    """Backup and restore settings page (admin only)."""
    return render_template('settings/backup.html')


@main_bp.route('/api/backups/available-indices', methods=['GET'])
@login_required
@admin_required
def get_available_indices():
    """Get list of all available indices for backup."""
    from app.services.elasticsearch_service import ElasticsearchService
    
    es_service = ElasticsearchService()
    
    try:
        # Get all indices with the app prefix
        all_indices = es_service.client.indices.get_alias(index="*")
        available_indices = [idx for idx in all_indices.keys() if idx.startswith(ElasticsearchService.INDEX_PREFIX)]
        # Remove prefix for display
        clean_names = [idx.replace(ElasticsearchService.INDEX_PREFIX, '') for idx in available_indices]
        return jsonify({
            'success': True,
            'indices': sorted(clean_names)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@main_bp.route('/api/backups', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_backups():
    """Get list of backups or create a new backup."""
    backup_service = BackupService()
    
    if request.method == 'GET':
        backups = backup_service.list_backups()
        return jsonify({'backups': backups})
    
    # POST: Create new backup
    data = request.get_json() or {}
    indices = data.get('indices', None)
    
    result = backup_service.create_backup(include_indices=indices)
    status_code = 200 if result.get('success') else 400
    
    return jsonify(result), status_code


@main_bp.route('/api/backups/<backup_id>', methods=['GET', 'DELETE'])
@login_required
@admin_required
def manage_backup(backup_id):
    """Get or delete a specific backup."""
    backup_service = BackupService()
    
    if request.method == 'DELETE':
        result = backup_service.delete_backup(backup_id)
        status_code = 200 if result.get('success') else 400
        return jsonify(result), status_code
    
    # GET: Get backup info (handled by /info endpoint)
    backups = backup_service.list_backups()
    for backup in backups:
        if backup['backup_id'] == backup_id:
            return jsonify(backup)
    
    return jsonify({'error': 'Backup not found'}), 404


@main_bp.route('/api/backups/<backup_id>/info', methods=['GET'])
@login_required
@admin_required
def get_backup_info(backup_id):
    """Get detailed information about a backup."""
    backup_service = BackupService()
    info = backup_service.get_backup_info(backup_id)
    
    if 'error' in info:
        return jsonify(info), 404
    
    return jsonify(info)


@main_bp.route('/api/backups/restore', methods=['POST'])
@login_required
@admin_required
def restore_backup():
    """Restore a backup."""
    data = request.get_json() or {}
    backup_id = data.get('backup_id')
    overwrite = data.get('overwrite', False)
    
    if not backup_id:
        return jsonify({'success': False, 'error': 'backup_id is required'}), 400
    
    backup_service = BackupService()
    result = backup_service.restore_backup(backup_id, overwrite=overwrite)
    status_code = 200 if result.get('success') else 400
    
    return jsonify(result), status_code


@main_bp.route('/api/backups/<backup_id>/download', methods=['GET'])
@login_required
@admin_required
def download_backup(backup_id):
    """Download a backup file."""
    from flask import send_file
    import os
    
    backup_service = BackupService()
    
    # Get the backup file path
    backup_path = backup_service.backup_dir / f'{backup_id}.tar.gz'
    
    # Verify the path exists and is a file
    if not backup_path.exists():
        current_app.logger.error(f"Backup file not found: {backup_path}")
        return jsonify({'error': 'Backup not found'}), 404
    
    if not backup_path.is_file():
        current_app.logger.error(f"Backup path is not a file: {backup_path}")
        return jsonify({'error': 'Backup path is invalid'}), 400
    
    try:
        # Convert to string path for send_file
        backup_path_str = str(backup_path.resolve())
        
        # Verify file is readable
        if not os.access(backup_path_str, os.R_OK):
            current_app.logger.error(f"Backup file not readable: {backup_path_str}")
            return jsonify({'error': 'Cannot read backup file'}), 400
        
        return send_file(
            backup_path_str,
            mimetype='application/gzip',
            as_attachment=True,
            download_name=f'{backup_id}.tar.gz'
        )
    except Exception as e:
        current_app.logger.error(f"Error downloading backup {backup_id}: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 400


@main_bp.route('/api/backups/upload', methods=['POST'])
@login_required
@admin_required
def upload_backup():
    """Upload and restore a backup file."""
    from werkzeug.utils import secure_filename
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    overwrite = request.form.get('overwrite', 'false').lower() == 'true'
    
    if not file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.tar.gz'):
        return jsonify({'success': False, 'error': 'File must be a .tar.gz backup'}), 400
    
    backup_service = BackupService()
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        backup_path = backup_service.backup_dir / filename
        file.save(str(backup_path))
        
        # Extract backup ID from filename
        backup_id = filename.replace('.tar.gz', '')
        
        # Restore the backup
        result = backup_service.restore_backup(backup_id, overwrite=overwrite)
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Backup uploaded and restored successfully',
                'backup_id': backup_id,
                'details': result
            })
        else:
            # Clean up on restore failure
            if backup_path.exists():
                backup_path.unlink()
            return jsonify({
                'success': False,
                'error': result.get('error'),
                'message': result.get('message')
            }), 400
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to upload backup'
        }), 400


@main_bp.route('/reports')
@login_required
def reports_dashboard():
    """Reports dashboard page."""
    return render_template('reports_dashboard.html')


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
            result = es.get('elaslip_app_config', config_id)
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
        es.index('elaslip_app_config', config_id, config)
        return jsonify({'message': 'Configuration saved', 'config': config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/api/elasticsearch/stats', methods=['GET'])
@login_required
@permission_required('audit.view')
def elasticsearch_stats():
    """Get Elasticsearch cluster health and indices statistics."""
    try:
        from app.services.elasticsearch_service import ElasticsearchService
        es_service = ElasticsearchService()
        
        # Get cluster health
        cluster_health = es_service.client.cluster.health()
        
        # Get indices stats
        indices_stats = es_service.client.indices.stats(expand_wildcards='all')
        
        # Build indices info
        indices_info = {}
        if 'indices' in indices_stats:
            for index_name, index_data in indices_stats['indices'].items():
                if index_name.startswith('.'):
                    continue  # Skip system indices
                
                indices_info[index_name] = {
                    'health': cluster_health.get('indices', {}).get(index_name, {}).get('status', 'unknown'),
                    'status': 'open',  # Most indices are open
                    'docs_count': index_data.get('primaries', {}).get('docs', {}).get('count', 0),
                    'size_in_bytes': index_data.get('primaries', {}).get('store', {}).get('size_in_bytes', 0),
                    'number_of_shards': index_data.get('index', {}).get('number_of_shards', 1),
                    'number_of_replicas': index_data.get('index', {}).get('number_of_replicas', 0)
                }
        
        return jsonify({
            'status': 'success',
            'cluster_health': {
                'status': cluster_health.get('status', 'unknown'),
                'number_of_nodes': cluster_health.get('number_of_nodes', 0),
                'number_of_data_nodes': cluster_health.get('number_of_data_nodes', 0),
                'active_primary_shards': cluster_health.get('active_primary_shards', 0),
                'active_shards': cluster_health.get('active_shards', 0),
                'unassigned_shards': cluster_health.get('unassigned_shards', 0),
                'number_of_indices': cluster_health.get('number_of_indices', 0)
            },
            'indices': indices_info
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


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
    valid_roles = get_all_valid_roles()
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
        valid_roles = get_all_valid_roles()
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
    
    # If user is editing themselves, reload current_user to reflect any role/permission changes
    if user_id == current_user.id and 'role' in update_data:
        # Reload current_user from database to get updated properties
        current_user.is_admin = user.is_admin
        current_user.role = user.role
        current_user._permissions = None  # Reset cached permissions
    
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
@permission_required('snippet.view', 'snippet.create', require_all=False)
def snippets_library():
    """Markdown snippets library page."""
    return render_template('snippets/library.html')


@main_bp.route('/report')
@login_required
def view_report():
    """View generated report page."""
    from app.decorators import check_permission
    can_regenerate_report = check_permission('report.generate_llm')
    can_regenerate_checklist = check_permission('checklist.generate_llm')
    return render_template('report.html', 
                           can_regenerate_report=can_regenerate_report,
                           can_regenerate_checklist=can_regenerate_checklist)