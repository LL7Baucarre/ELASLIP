"""Main routes for web interface."""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
import os
from dotenv import load_dotenv, set_key

from app.services.ioc_service import IOCService
from app.services.stix_service import STIXService
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


@main_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Docker and monitoring."""
    try:
        from app.config import Config
        return jsonify({
            'status': 'healthy',
            'version': Config.APP_VERSION
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@main_bp.route('/api/version', methods=['GET'])
def get_version():
    """Get application version."""
    from app.config import Config
    return jsonify({
        'version': Config.APP_VERSION,
        'app_name': current_app.config.get('SITE_NAME', 'IOC Manager')
    }), 200


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
    from app.services.elasticsearch_service import ElasticsearchService
    stix_service = STIXService()
    case_service = CaseService()
    checklist_service = ChecklistService()
    es = ElasticsearchService()
    
    # Get entity counts - now counting STIX objects instead of legacy IOCs
    try:
        total_stix = es.count('stix_objects')
    except:
        total_stix = 0
    
    try:
        cases_result = es.search('cases', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 0
        })
        total_cases = cases_result['hits']['total']['value']
    except:
        total_cases = 0
    
    try:
        incidents_result = es.search('incidents', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 0
        })
        total_incidents = incidents_result['hits']['total']['value']
    except:
        total_incidents = 0
    
    try:
        checklists_result = es.search('checklists', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'completed'}},
                        {'term': {'status': 'archived'}}
                    ]
                }
            },
            'size': 0
        })
        total_checklists = checklists_result['hits']['total']['value']
    except:
        total_checklists = 0
    
    # Get stats by status/severity (exclude closed items)
    try:
        cases_by_status = es.aggregate('cases', {
            'by_status': {
                'terms': {'field': 'status', 'size': 10}
            }
        }, query={
            'bool': {
                'must_not': [
                    {'term': {'status': 'closed'}}
                ]
            }
        })
        cases_status_stats = {b['key']: b['doc_count'] 
                             for b in cases_by_status.get('aggregations', {}).get('by_status', {}).get('buckets', [])}
    except:
        cases_status_stats = {}
    
    try:
        incidents_by_severity = es.aggregate('incidents', {
            'by_severity': {'terms': {'field': 'severity', 'size': 10}}
        }, query={
            'bool': {
                'must_not': [
                    {'term': {'status': 'closed'}}
                ]
            }
        })
        incidents_severity_stats = {b['key']: b['doc_count'] 
                                   for b in incidents_by_severity.get('aggregations', {}).get('by_severity', {}).get('buckets', [])}
    except:
        incidents_severity_stats = {}
    
    # Get STIX objects by type
    try:
        stix_by_type = es.aggregate('stix_objects', {
            'by_type': {'terms': {'field': 'type', 'size': 20}}
        })
        stix_type_stats = {b['key']: b['doc_count'] 
                            for b in stix_by_type.get('aggregations', {}).get('by_type', {}).get('buckets', [])}
    except:
        stix_type_stats = {}
    
    # Get STIX objects by labels
    try:
        stix_by_labels = es.aggregate('stix_objects', {
            'by_labels': {'terms': {'field': 'labels', 'size': 50}}
        })
        labels_stats = {b['key']: b['doc_count'] 
                        for b in stix_by_labels.get('aggregations', {}).get('by_labels', {}).get('buckets', [])}
    except:
        labels_stats = {}
    
    # Create stats object for template
    stats = {
        'by_label': labels_stats
    }
    
    # Get recent STIX objects
    try:
        recent_stix = stix_service.list(page=1, per_page=5)
        template_stix = recent_stix.get('items', [])
    except Exception as e:
        logger.exception("Error fetching recent STIX objects: %s", e)
        template_stix = []
    
    # Get recent cases (exclude closed cases)
    try:
        recent_cases_result = es.search('cases', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_cases = [{'id': hit['_id'], 'entity_type': 'case', **hit['_source']} 
                       for hit in recent_cases_result['hits']['hits']]
    except:
        recent_cases = []
    
    # Get recent incidents (exclude closed incidents)
    try:
        recent_incidents_result = es.search('incidents', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_incidents = [{'id': hit['_id'], 'entity_type': 'incident', **hit['_source']} 
                           for hit in recent_incidents_result['hits']['hits']]
    except:
        recent_incidents = []
    
    # Get recent checklists (exclude completed/archived checklists)
    try:
        recent_checklists_result = es.search('checklists', {
            'query': {
                'bool': {
                    'must_not': [
                        {'term': {'status': 'completed'}},
                        {'term': {'status': 'archived'}}
                    ]
                }
            },
            'size': 5,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        recent_checklists = [{'id': hit['_id'], 'entity_type': 'checklist', **hit['_source']} 
                            for hit in recent_checklists_result['hits']['hits']]
    except:
        recent_checklists = []
    
    # Get assignments for current user - with filters
    assigned_cases = []
    assigned_incidents = []
    assigned_checklists = []
    
    try:
        # Get cases assigned to current user (exclude closed)
        cases_assigned_result = es.search('cases', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'assignee_name': current_user.username}}
                    ],
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 100,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        assigned_cases = [hit['_source'] | {'id': hit['_id']} 
                         for hit in cases_assigned_result['hits']['hits']]
    except Exception as e:
        logger.exception("Error fetching assigned cases: %s", e)
    
    try:
        # Get incidents assigned to current user (exclude closed)
        incidents_assigned_result = es.search('incidents', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'assignee_name': current_user.username}}
                    ],
                    'must_not': [
                        {'term': {'status': 'closed'}}
                    ]
                }
            },
            'size': 100,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        assigned_incidents = [hit['_source'] | {'id': hit['_id']} 
                             for hit in incidents_assigned_result['hits']['hits']]
    except Exception as e:
        logger.exception("Error fetching assigned incidents: %s", e)
    
    try:
        # Get checklists assigned to current user (exclude completed/archived)
        checklists_assigned_result = es.search('checklists', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'assigned_to_name': current_user.username}}
                    ],
                    'must_not': [
                        {'term': {'status': 'completed'}},
                        {'term': {'status': 'archived'}}
                    ]
                }
            },
            'size': 100,
            'sort': [{'updated_at': {'order': 'desc'}}]
        })
        assigned_checklists = [hit['_source'] | {'id': hit['_id']} 
                              for hit in checklists_assigned_result['hits']['hits']]
        
        # Calculate progress for each checklist
        for checklist in assigned_checklists:
            items = checklist.get('items', [])
            if items:
                completed_count = sum(1 for item in items if item.get('completed', False))
                checklist['progress'] = int((completed_count / len(items)) * 100)
            else:
                checklist['progress'] = 0
    except Exception as e:
        logger.exception("Error fetching assigned checklists: %s", e)
    
    # Build assigned_recent from assigned items only
    assigned_recent = []
    
    for case in assigned_cases:
        assigned_recent.append({
            'id': case.get('id'),
            'entity_type': 'case',
            'name': case.get('title', 'Untitled'),
            'status': case.get('status', ''),
            'updated_at': case.get('updated_at', '')
        })
    for incident in assigned_incidents:
        assigned_recent.append({
            'id': incident.get('id'),
            'entity_type': 'incident',
            'name': incident.get('title', 'Unnamed'),
            'severity': incident.get('severity', ''),
            'updated_at': incident.get('updated_at', '')
        })
    for checklist in assigned_checklists:
        assigned_recent.append({
            'id': checklist.get('id'),
            'entity_type': 'checklist',
            'name': checklist.get('title', 'Unnamed'),
            'status': checklist.get('status', ''),
            'updated_at': checklist.get('updated_at', '')
        })
    
    # Sort by updated_at descending and take top 10
    assigned_recent = sorted(assigned_recent, key=lambda x: x.get('updated_at', ''), reverse=True)[:10]
    
    # Keep all_recent for backward compatibility but use assigned_recent for display
    all_recent = assigned_recent
    
    # Get unresolved public submissions
    try:
        submissions_result = es.search('submissions', {
            'query': {'term': {'status': 'pending'}},
            'size': 5,
            'sort': [{'created_at': {'order': 'desc'}}]
        })
        unresolved_submissions = [hit['_source'] | {'id': hit['_id']} 
                                  for hit in submissions_result['hits']['hits']]
    except:
        unresolved_submissions = []
    
    return render_template('dashboard.html', 
                          total_stix=total_stix,
                          total_iocs=total_stix,  # Backward compatibility
                          total_cases=total_cases,
                          total_incidents=total_incidents,
                          total_checklists=total_checklists,
                          cases_status_stats=cases_status_stats,
                          incidents_severity_stats=incidents_severity_stats,
                          stix_type_stats=stix_type_stats,
                          iocs_threat_stats=stix_type_stats,  # Backward compatibility
                          stats=stats,
                          all_recent=all_recent,
                          unresolved_submissions=unresolved_submissions,
                          assigned_cases=assigned_cases,
                          assigned_incidents=assigned_incidents,
                          assigned_checklists=assigned_checklists)


@main_bp.route('/iocs')
@login_required
def iocs_list():
    """Redirect to STIX objects list (IOCs deprecated)."""
    return redirect(url_for('stix.list_stix_objects_page'))


@main_bp.route('/iocs/add')
@login_required
def iocs_add():
    """Redirect to STIX object creation (IOCs deprecated)."""
    return redirect(url_for('stix.add_stix_object_page'))


@main_bp.route('/iocs/<ioc_id>')
@login_required
def iocs_detail(ioc_id):
    """Redirect to STIX object detail (IOCs deprecated)."""
    return redirect(url_for('stix.stix_object_detail_page', object_id=ioc_id))


@main_bp.route('/iocs/graph')
@login_required
def iocs_graph():
    """IOC graph visualization page - now uses STIX objects."""
    return render_template('stix/graph.html')


@main_bp.route('/activity')
@login_required
@permission_required('admin.audit')
def activity_timeline():
    """Activity timeline page."""
    return render_template('activity.html')


@main_bp.route('/api/iocs/graph-data')
@main_bp.route('/api/stix/graph-data')
@login_required
def get_graph_data():
    """Get STIX objects and relationships for graph visualization, including cases and incidents."""
    from app.services.case_service import CaseService
    from app.services.elasticsearch_service import ElasticsearchService
    
    stix_service = STIXService()
    case_service = CaseService()
    es = ElasticsearchService()
    
    # Get all STIX objects with limit
    limit = request.args.get('limit', default=100, type=int)
    all_stix = stix_service.list_sdos(page=1, size=limit)
    
    nodes = []
    edges = []
    node_ids = {}
    edge_set = set()
    
    # Create nodes from STIX objects
    for obj in all_stix.get('items', []):
        node_id = obj.get('id')
        node_ids[node_id] = {'type': 'stix', 'data': obj}
        
        # Build classes with STIX type
        stix_type = obj.get('type', 'unknown').replace('-', '_')
        classes = f"stix-{stix_type}"
        
        nodes.append({
            'data': {
                'id': node_id,
                'label': str(obj.get('name', obj.get('value', obj.get('pattern', 'Unknown')))),
                'type': str(obj.get('type', 'unknown')),
                'entity_type': 'stix'
            },
            'classes': classes
        })
    
    # Get all cases
    try:
        all_cases = case_service.es.search(
            'cases',
            {
                'size': 1000,
                'query': {'match_all': {}}
            }
        )
        
        for hit in all_cases.get('hits', {}).get('hits', []):
            case_id = hit.get('_id')
            case_data = hit.get('_source', {})
            node_ids[case_id] = {'type': 'case', 'data': case_data}
            
            nodes.append({
                'data': {
                    'id': case_id,
                    'label': str(case_data.get('title', 'Unknown Case')),
                    'entity_type': 'case',
                    'status': case_data.get('status', 'unknown')
                },
                'classes': 'case'
            })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch cases: {str(e)}")
    
    # Get all incidents
    try:
        all_incidents = case_service.es.search(
            'incidents',
            {
                'size': 1000,
                'query': {'match_all': {}}
            }
        )
        
        for hit in all_incidents.get('hits', {}).get('hits', []):
            incident_id = hit.get('_id')
            incident_data = hit.get('_source', {})
            node_ids[incident_id] = {'type': 'incident', 'data': incident_data}
            
            nodes.append({
                'data': {
                    'id': incident_id,
                    'label': str(incident_data.get('title', 'Unknown Incident')),
                    'entity_type': 'incident',
                    'severity': incident_data.get('severity', 'unknown')
                },
                'classes': 'incident'
            })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch incidents: {str(e)}")
    
    # Get STIX 2.1 relationships from Elasticsearch
    try:
        # Get STIX relationships
        all_relations = es.search(
            'stix_relationships',
            {
                'size': 10000,
                'query': {'match_all': {}}
            }
        )
        
        total_relations = all_relations.get('hits', {}).get('total', {}).get('value', 0)
        current_app.logger.info(f"Total STIX relationships found: {total_relations}")
        
        # Create edges from STIX relationships
        for rel in all_relations.get('hits', {}).get('hits', []):
            rel_data = rel.get('_source', {})
            rel_id = rel.get('_id', '')
            
            # source_ref/target_ref are in indicator--uuid format, same as node IDs
            source_ref = rel_data.get('source_ref', '')
            target_ref = rel_data.get('target_ref', '')
            relationship_type = rel_data.get('relationship_type', 'related-to')
            
            # Only add edge if both nodes exist (use full indicator--uuid format)
            if source_ref and target_ref and source_ref in node_ids and target_ref in node_ids:
                edge_id = f"{source_ref}-{target_ref}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_ref,
                            'target': target_ref,
                            'label': relationship_type
                        },
                        'classes': f"relation-{relationship_type.replace('-', '_')}"
                    })
    except Exception as e:
        current_app.logger.warning(f"Could not fetch STIX relationships: {str(e)}")
    
    # Get STIX-Case relations from case stix_ids or ioc_ids
    try:
        for case_id, node_info in node_ids.items():
            if node_info['type'] == 'case':
                case_data = node_info['data']
                stix_ids = case_data.get('stix_ids', case_data.get('ioc_ids', []))
                for stix_id in stix_ids:
                    if stix_id in node_ids and node_ids[stix_id]['type'] == 'stix':
                        edge_id = f"{stix_id}-{case_id}"
                        if edge_id not in edge_set:
                            edge_set.add(edge_id)
                            edges.append({
                                'data': {
                                    'id': edge_id,
                                    'source': stix_id,
                                    'target': case_id,
                                    'label': 'found-in-case'
                                },
                                'classes': 'relation-found_in_case'
                            })
    except Exception as e:
        current_app.logger.warning(f"Could not process STIX-Case relations: {str(e)}")
    
    # Get STIX-Incident relations from incident stix_ids or ioc_ids
    try:
        for incident_id, node_info in node_ids.items():
            if node_info['type'] == 'incident':
                incident_data = node_info['data']
                stix_ids = incident_data.get('stix_ids', incident_data.get('ioc_ids', []))
                for stix_id in stix_ids:
                    if stix_id in node_ids and node_ids[stix_id]['type'] == 'stix':
                        edge_id = f"{stix_id}-{incident_id}"
                        if edge_id not in edge_set:
                            edge_set.add(edge_id)
                            edges.append({
                                'data': {
                                    'id': edge_id,
                                    'source': stix_id,
                                    'target': incident_id,
                                    'label': 'found-in-incident'
                                },
                                'classes': 'relation-found_in_incident'
                            })
    except Exception as e:
        current_app.logger.warning(f"Could not process STIX-Incident relations: {str(e)}")
    
    current_app.logger.info(f"Final graph: {len(nodes)} nodes, {len(edges)} edges")
    
    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'count': len(nodes),
        'relations_count': len(edges)
    })


@main_bp.route('/api/debug/relations')
@login_required
def debug_relations():
    """Debug endpoint to check STIX 2.1 relationships in Elasticsearch."""
    from app.services.elasticsearch_service import ElasticsearchService
    es = ElasticsearchService()
    
    try:
        all_relations = es.search(
            'stix_relationships',
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
    """Get graph data for a specific IOC and its relations (including cases and incidents)."""
    from app.services.case_service import CaseService
    
    ioc_service = IOCService()
    case_service = CaseService()
    
    nodes = []
    edges = []
    edge_set = set()
    node_ids = set()
    
    try:
        # Get the main IOC
        main_ioc = ioc_service.get(ioc_id)
        if not main_ioc:
            return jsonify({'error': 'IOC not found'}), 404
        
        # Add main IOC as central node
        nodes.append({
            'data': {
                'id': main_ioc['id'],
                'label': str(main_ioc.get('ioc_value', main_ioc.get('value', 'Unknown'))),
                'type': str(main_ioc.get('ioc_type', 'unknown')),
                'threat_level': str(main_ioc.get('threat_level', 'unknown')),
                'confidence': str(main_ioc.get('confidence', '')),
                'tlp': str(main_ioc.get('tlp', '')),
                'entity_type': 'ioc'
            },
            'classes': f"ioc-{main_ioc.get('ioc_type', 'unknown').replace('-', '_')}"
        })
        node_ids.add(ioc_id)
        
        # Build STIX ref for this IOC (ioc_id already has indicator-- prefix)
        ioc_ref = ioc_id
        
        # Get all STIX relationships for this IOC
        all_relations = ioc_service.es.search(
            'stix_relationships',
            {'size': 10000, 'query': {'match_all': {}}}
        )
        
        related_ioc_ids = set()
        
        # Find STIX relationships where this IOC is source or target
        for rel in all_relations.get('hits', {}).get('hits', []):
            rel_data = rel.get('_source', {})
            source_ref = rel_data.get('source_ref', '')
            target_ref = rel_data.get('target_ref', '')
            relationship_type = rel_data.get('relationship_type', 'related-to')
            
            # source_ref and target_ref are in indicator--uuid format
            # ioc_id is also in indicator--uuid format
            source_id = source_ref  # Keep full ID for node creation
            target_id = target_ref  # Keep full ID for node creation
            
            # Check if this IOC is involved in the relationship
            if source_ref == ioc_id and target_ref:
                related_ioc_ids.add(target_ref)
                edge_id = f"{source_ref}-{target_ref}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_ref,
                            'target': target_ref,
                            'label': relationship_type
                        },
                        'classes': f"relation-{relationship_type.replace('-', '_')}"
                    })
            elif target_ref == ioc_id and source_ref:
                related_ioc_ids.add(source_ref)
                edge_id = f"{source_ref}-{target_ref}"
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append({
                        'data': {
                            'id': edge_id,
                            'source': source_ref,
                            'target': target_ref,
                            'label': relationship_type
                        },
                        'classes': f"relation-{relationship_type.replace('-', '_')}"
                    })
        
        # Load related IOCs
        for related_id in related_ioc_ids:
            try:
                related_ioc = ioc_service.get(related_id)
                if related_ioc:
                    nodes.append({
                        'data': {
                            'id': related_ioc['id'],
                            'label': str(related_ioc.get('ioc_value', related_ioc.get('value', 'Unknown'))),
                            'type': str(related_ioc.get('ioc_type', 'unknown')),
                            'threat_level': str(related_ioc.get('threat_level', 'unknown')),
                            'confidence': str(related_ioc.get('confidence', '')),
                            'tlp': str(related_ioc.get('tlp', '')),
                            'entity_type': 'ioc'
                        },
                        'classes': f"ioc-{related_ioc.get('ioc_type', 'unknown').replace('-', '_')}"
                    })
                    node_ids.add(related_id)
            except:
                pass
        
        # Get cases that contain this IOC
        try:
            all_cases = case_service.es.search(
                'cases',
                {'size': 1000, 'query': {'match_all': {}}}
            )
            
            for hit in all_cases.get('hits', {}).get('hits', []):
                case_id = hit.get('_id')
                case_data = hit.get('_source', {})
                ioc_ids = case_data.get('ioc_ids', [])
                
                if ioc_id in ioc_ids:
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
                    
                    # Add edge from IOC to case
                    edge_id = f"{ioc_id}-{case_id}"
                    if edge_id not in edge_set:
                        edge_set.add(edge_id)
                        edges.append({
                            'data': {
                                'id': edge_id,
                                'source': ioc_id,
                                'target': case_id,
                                'label': 'found-in-case'
                            },
                            'classes': 'relation-found_in_case'
                        })
        except Exception as e:
            current_app.logger.warning(f"Could not fetch cases: {str(e)}")
        
        # Get incidents that contain this IOC
        try:
            all_incidents = case_service.es.search(
                'incidents',
                {'size': 1000, 'query': {'match_all': {}}}
            )
            
            for hit in all_incidents.get('hits', {}).get('hits', []):
                incident_id = hit.get('_id')
                incident_data = hit.get('_source', {})
                ioc_ids = incident_data.get('ioc_ids', [])
                
                if ioc_id in ioc_ids:
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
                    
                    # Add edge from IOC to incident
                    edge_id = f"{ioc_id}-{incident_id}"
                    if edge_id not in edge_set:
                        edge_set.add(edge_id)
                        edges.append({
                            'data': {
                                'id': edge_id,
                                'source': ioc_id,
                                'target': incident_id,
                                'label': 'found-in-incident'
                            },
                            'classes': 'relation-found_in_incident'
                        })
        except Exception as e:
            current_app.logger.warning(f"Could not fetch incidents: {str(e)}")
        
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


@main_bp.route('/api/settings/oauth', methods=['GET', 'PUT'])
@login_required
@admin_required
def api_settings_oauth():
    """Get or update OAuth settings (admin only)."""
    if request.method == 'GET':
        # Return current OAuth settings
        from app.config import Config
        return jsonify({
            'oauth_enabled': current_app.config.get('OAUTH_ENABLED', False),
            'oauth_encryption_key_set': current_app.config.get('OAUTH_ENCRYPTION_KEY') is not None,
            'oauth_auto_create_user': current_app.config.get('OAUTH_AUTO_CREATE_USER', True),
            'oauth_auto_link_by_email': current_app.config.get('OAUTH_AUTO_LINK_BY_EMAIL', False),
            'oauth_default_role': current_app.config.get('OAUTH_DEFAULT_ROLE', 'viewer'),
            'oauth_google_enabled': current_app.config.get('OAUTH_GOOGLE_ENABLED', False),
            'oauth_google_client_id': current_app.config.get('OAUTH_GOOGLE_CLIENT_ID', ''),
            'oauth_google_client_secret': current_app.config.get('OAUTH_GOOGLE_CLIENT_SECRET', ''),
            'oauth_github_enabled': current_app.config.get('OAUTH_GITHUB_ENABLED', False),
            'oauth_github_client_id': current_app.config.get('OAUTH_GITHUB_CLIENT_ID', ''),
            'oauth_github_client_secret': current_app.config.get('OAUTH_GITHUB_CLIENT_SECRET', ''),
            'oauth_oidc_enabled': current_app.config.get('OAUTH_OIDC_ENABLED', False),
            'oauth_oidc_client_id': current_app.config.get('OAUTH_OIDC_CLIENT_ID', ''),
            'oauth_oidc_client_secret': current_app.config.get('OAUTH_OIDC_CLIENT_SECRET', ''),
            'oauth_oidc_discovery_url': current_app.config.get('OAUTH_OIDC_DISCOVERY_URL', ''),
            'oauth_oidc_provider_name': current_app.config.get('OAUTH_OIDC_PROVIDER_NAME', 'OIDC'),
        })
    
    # PUT - Update OAuth settings
    data = request.get_json()
    
    # Update global settings
    if 'oauth_enabled' in data:
        current_app.config['OAUTH_ENABLED'] = data['oauth_enabled']
    if 'oauth_auto_create_user' in data:
        current_app.config['OAUTH_AUTO_CREATE_USER'] = data['oauth_auto_create_user']
    if 'oauth_auto_link_by_email' in data:
        current_app.config['OAUTH_AUTO_LINK_BY_EMAIL'] = data['oauth_auto_link_by_email']
    if 'oauth_default_role' in data:
        current_app.config['OAUTH_DEFAULT_ROLE'] = data['oauth_default_role']
    
    # Update Google OAuth settings
    if 'oauth_google_enabled' in data:
        current_app.config['OAUTH_GOOGLE_ENABLED'] = data['oauth_google_enabled']
    if 'oauth_google_client_id' in data:
        current_app.config['OAUTH_GOOGLE_CLIENT_ID'] = data['oauth_google_client_id']
    if 'oauth_google_client_secret' in data:
        current_app.config['OAUTH_GOOGLE_CLIENT_SECRET'] = data['oauth_google_client_secret']
    
    # Update GitHub OAuth settings
    if 'oauth_github_enabled' in data:
        current_app.config['OAUTH_GITHUB_ENABLED'] = data['oauth_github_enabled']
    if 'oauth_github_client_id' in data:
        current_app.config['OAUTH_GITHUB_CLIENT_ID'] = data['oauth_github_client_id']
    if 'oauth_github_client_secret' in data:
        current_app.config['OAUTH_GITHUB_CLIENT_SECRET'] = data['oauth_github_client_secret']
    
    # Update OIDC OAuth settings
    if 'oauth_oidc_enabled' in data:
        current_app.config['OAUTH_OIDC_ENABLED'] = data['oauth_oidc_enabled']
    if 'oauth_oidc_client_id' in data:
        current_app.config['OAUTH_OIDC_CLIENT_ID'] = data['oauth_oidc_client_id']
    if 'oauth_oidc_client_secret' in data:
        current_app.config['OAUTH_OIDC_CLIENT_SECRET'] = data['oauth_oidc_client_secret']
    if 'oauth_oidc_discovery_url' in data:
        current_app.config['OAUTH_OIDC_DISCOVERY_URL'] = data['oauth_oidc_discovery_url']
    if 'oauth_oidc_provider_name' in data:
        current_app.config['OAUTH_OIDC_PROVIDER_NAME'] = data['oauth_oidc_provider_name']
    
    return jsonify({
        'message': 'OAuth settings updated successfully (note: these changes are temporary, add to .env for persistence)'
    })


@main_bp.route('/api/settings/oauth/roles', methods=['GET'])
@login_required
@admin_required
def api_oauth_roles():
    """Get available roles for OAuth default assignment."""
    from app.services.rbac_service import RBACService
    
    rbac_service = RBACService()
    roles = rbac_service.get_all_roles()
    
    return jsonify({
        'roles': [{'name': role.get('name'), 'description': role.get('description', '')} for role in roles]
    })


@main_bp.route('/api/settings/shodan', methods=['POST', 'DELETE'])
@login_required
@admin_required
def api_shodan_settings():
    """Manage Shodan API configuration."""
    if request.method == 'POST':
        data = request.get_json()
        api_key = data.get('api_key', '').strip()
        enabled = data.get('enabled', False)
        
        if not api_key:
            return jsonify({'message': 'API key is required', 'success': False}), 400
        
        # Update application config (temporary, until server restart)
        current_app.config['SHODAN_API_KEY'] = api_key
        current_app.config['SHODAN_ENABLED'] = enabled
        
        # Persist to .env file
        env_file = '.env'
        # Create .env file if it doesn't exist
        if not os.path.exists(env_file):
            open(env_file, 'a').close()
        
        if os.path.exists(env_file):
            set_key(env_file, 'SHODAN_API_KEY', api_key)
            set_key(env_file, 'SHODAN_ENABLED', 'true' if enabled else 'false')
        
        return jsonify({
            'message': 'Shodan configuration saved successfully',
            'success': True,
            'enabled': enabled
        })
    
    elif request.method == 'DELETE':
        # Clear Shodan configuration
        current_app.config['SHODAN_API_KEY'] = ''
        current_app.config['SHODAN_ENABLED'] = False
        
        # Remove from .env file
        env_file = '.env'
        if os.path.exists(env_file):
            set_key(env_file, 'SHODAN_API_KEY', '')
            set_key(env_file, 'SHODAN_ENABLED', 'false')
        
        return jsonify({
            'message': 'Shodan configuration cleared',
            'success': True
        })


@main_bp.route('/settings/oauth')
@login_required
@admin_required
def settings_oauth():
    """OAuth configuration page (admin only)."""
    return render_template('settings/oauth.html')


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


@main_bp.route('/settings/shodan')
@login_required
@admin_required
def settings_shodan():
    """Shodan API settings page (admin only)."""
    from app.config import Config
    return render_template('settings/shodan.html', shodan_enabled=Config.SHODAN_ENABLED)


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
                'number_of_indices': len(indices_info)
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


@main_bp.route('/docs')
@login_required
def docs():
    """Documentation page with STIX 2.1, Cases, Incidents, and Checklists guides."""
    return render_template('docs.html')


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
    from app.services.checklist_template_service import ChecklistTemplateService
    template_service = ChecklistTemplateService()
    
    # Load available checklist templates for incident response
    checklists = template_service.list_templates(page=1, per_page=100, include_public=True)
    
    return render_template('incidents/new.html', checklist_templates=checklists.get('items', []))


@main_bp.route('/incidents/<incident_id>')
@login_required
def incidents_detail(incident_id):
    """Incident detail page with report editor."""
    from app.services.case_service import IncidentService
    from app.services.checklist_service import ChecklistService
    from app.services.checklist_template_service import ChecklistTemplateService
    
    incident_service = IncidentService()
    incident = incident_service.get_incident(incident_id)
    
    if not incident:
        flash('Incident not found', 'error')
        return redirect(url_for('main.incidents_list'))
    
    # Load available checklist templates for creating new checklists
    template_service = ChecklistTemplateService()
    checklist_templates = template_service.list_templates(page=1, per_page=100, include_public=True)
    
    # Load linked checklists
    checklist_service = ChecklistService()
    linked_checklists = []
    if incident.get('checklist_ids'):
        for checklist_id in incident.get('checklist_ids', []):
            checklist = checklist_service.get_checklist(checklist_id)
            if checklist:
                linked_checklists.append(checklist)
    
    return render_template('incidents/detail.html', incident=incident, 
                         checklist_templates=checklist_templates.get('items', []),
                         linked_checklists=linked_checklists)


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