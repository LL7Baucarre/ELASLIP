"""API routes for report generation."""

from flask import Blueprint, jsonify, request, abort, render_template
from flask_login import login_required, current_user
from app.auth import permission_required
from app.services.report_service import ReportService
from app.services.elasticsearch_service import ElasticsearchService
from app.config import Config
import os

bp = Blueprint('reports', __name__)
report_service = ReportService()
es_service = ElasticsearchService()


@bp.route('/api/reports/config', methods=['GET'])
@login_required
def get_report_config():
    """Get LLM configuration."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # Try to get from Elasticsearch first
    try:
        response = es_service.get('app_config', 'llm_config')
        if response and response.get('found'):
            return jsonify(response.get('_source', {}))
    except Exception:
        pass
    
    # Fall back to environment variables
    return jsonify({
        'enabled': os.getenv('LLM_ENABLED', 'false').lower() == 'true',
        'url': os.getenv('LLM_URL', 'http://ollama:11434'),
        'model': os.getenv('LLM_MODEL', 'mistral'),
        'configured': report_service.is_configured()
    })


@bp.route('/api/reports/config', methods=['POST'])
@login_required
def update_report_config():
    """Update LLM configuration."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    config = {
        'enabled': data.get('enabled', False),
        'url': data.get('url', 'http://ollama:11434'),
        'model': data.get('model', 'mistral'),
        'api_key': data.get('api_key', ''),
        'custom_prompt_ioc': data.get('custom_prompt_ioc', ''),
        'custom_prompt_case': data.get('custom_prompt_case', ''),
        'custom_prompt_incident': data.get('custom_prompt_incident', ''),
        'configured': False  # Will be set after testing
    }
    
    # Update environment variables
    os.environ['LLM_URL'] = config['url']
    os.environ['LLM_MODEL'] = config['model']
    os.environ['LLM_API_KEY'] = config['api_key']
    os.environ['LLM_ENABLED'] = 'true' if config['enabled'] else 'false'
    
    # Save to Elasticsearch for persistence
    try:
        es_service.index('app_config', 'llm_config', config)
    except Exception as e:
        return jsonify({'error': f'Failed to save configuration: {str(e)}'}), 500
    
    # Reinitialize report service with new config
    report_service.__init__()
    
    # Test connection
    config['configured'] = report_service.is_configured()
    
    return jsonify({
        'success': True,
        'message': 'LLM configuration saved',
        'configured': config['configured']
    })


@bp.route('/api/reports/test-connection', methods=['POST'])
@login_required
def test_llm_connection():
    """Test connection to LLM server."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    url = data.get('url', 'http://ollama:11434')
    model = data.get('model', 'mistral')
    
    try:
        import requests
        response = requests.get(f"{url}/api/tags", timeout=5)
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'HTTP {response.status_code}: {response.reason}'
            })
        
        api_data = response.json()
        models = api_data.get('models', [])
        model_exists = any(m['name'].split(':')[0] == model or model in m['name'] for m in models)
        
        if model_exists:
            return jsonify({
                'success': True,
                'models': [m['name'] for m in models]
            })
        else:
            available = [m['name'] for m in models]
            return jsonify({
                'success': False,
                'error': f'Model "{model}" not found. Available: {", ".join(available)}'
            })
    except requests.Timeout:
        return jsonify({
            'success': False,
            'error': f'Connection timeout to {url}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@bp.route('/api/reports/iocs/<ioc_id>', methods=['GET'])
@login_required
@permission_required('ioc.view')
def generate_ioc_report(ioc_id):
    """Launch async report generation for an IOC."""
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_ioc_report as task_generate_ioc
        # Launch async task
        task = task_generate_ioc.delay(ioc_id, current_user.username)
        return jsonify({
            'task_id': task.id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/cases/<case_id>', methods=['GET'])
@login_required
@permission_required('case.view')
def generate_case_report(case_id):
    """Launch async report generation for a case."""
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_case_report as task_generate_case
        # Launch async task
        task = task_generate_case.delay(case_id, current_user.username)
        return jsonify({
            'task_id': task.id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/incidents/<incident_id>', methods=['GET'])
@login_required
@permission_required('incident.view')
def generate_incident_report(incident_id):
    """Launch async report generation for an incident."""
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_incident_report as task_generate_incident
        # Launch async task
        task = task_generate_incident.delay(incident_id, current_user.username)
        return jsonify({
            'task_id': task.id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/status/<task_id>', methods=['GET'])
@login_required
def get_report_status(task_id):
    """Get status of a report generation task."""
    try:
        response = es_service.get('app_config', f'report_{task_id}')
        if not response or not response.get('found'):
            return jsonify({'error': 'Report not found'}), 404
        
        config = response.get('_source', {})
        
        # Check if user has permission to view this report
        if config.get('user_id') != current_user.username and not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/list', methods=['GET'])
@login_required
def list_reports():
    """List all reports for current user or all reports if admin."""
    try:
        # Simple query: just match all and filter by field existence
        if current_user.is_admin:
            query = {
                'query': {'match_all': {}},
                'sort': [{'created_at': {'order': 'desc'}}],
                'size': 100
            }
        else:
            query = {
                'query': {
                    'term': {'user_id': current_user.username}
                },
                'sort': [{'created_at': {'order': 'desc'}}],
                'size': 100
            }
        
        result = es_service.search('app_config', query)
        reports = []
        
        for hit in result.get('hits', {}).get('hits', []):
            doc = hit['_source']
            # Only include documents that are reports (have type, status fields)
            if 'type' in doc and 'status' in doc:
                doc['task_id'] = hit['_id'].replace('report_', '') if hit['_id'].startswith('report_') else hit['_id']
                reports.append(doc)
        
        return jsonify({'reports': reports, 'total': len(reports)})
    except Exception as e:
        import traceback
        return jsonify({'error': str(e), 'details': traceback.format_exc()}), 500


@bp.route('/api/reports/view/<task_id>', methods=['GET'])
@login_required
def view_report(task_id):
    """Get report data for viewing."""
    try:
        response = es_service.get('app_config', f'report_{task_id}')
        if not response or not response.get('found'):
            return jsonify({'error': 'Report not found'}), 404
        
        config = response.get('_source', {})
        
        # Check if user has permission to view this report
        if config.get('user_id') != current_user.username and not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403
        
        status = config.get('status')
        if status != 'completed':
            return jsonify({'error': f'Report not yet completed (status: {status})'}), 400
        
        report_data = config.get('report_data', {})
        report_data['task_id'] = task_id
        report_data['type'] = config.get('type')
        report_data['status'] = config.get('status')
        report_data['created_at'] = config.get('created_at')
        
        return jsonify(report_data)
    except Exception as e:
        import sys, traceback
        print(f"DEBUG: Exception in view_report: {str(e)}", file=sys.stderr)
        print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500
