"""API routes for report generation."""

from flask import Blueprint, jsonify, request, abort, render_template
from flask_login import login_required, current_user
from app.auth import permission_required
from app.services.report_service import ReportService
from app.services.elasticsearch_service import ElasticsearchService
from app.config import Config
from datetime import datetime
import os

bp = Blueprint('reports', __name__)
report_service = ReportService()
es_service = ElasticsearchService()


@bp.route('/api/reports/config', methods=['GET'])
@login_required
def get_report_config():
    """
    Get current LLM configuration (Admin only)
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    responses:
      200:
        description: LLM configuration retrieved
        schema:
          type: object
          properties:
            enabled:
              type: boolean
            provider:
              type: string
            url:
              type: string
            model:
              type: string
            api_key:
              type: string
            generation_language:
              type: string
            custom_prompt_ioc:
              type: string
            custom_prompt_case:
              type: string
            custom_prompt_incident:
              type: string
            custom_prompt_checklist:
              type: string
            configured:
              type: boolean
      403:
        description: Admin access required
    """
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # Try to get from Elasticsearch first
    try:
        response = es_service.get('elasmisp_app_config', 'llm_config')
        if response and response.get('found'):
            config = response.get('_source', {})
            # Add configured status
            config['configured'] = report_service.is_configured()
            return jsonify(config)
    except Exception:
        pass
    
    # Fall back to environment variables
    return jsonify({
        'enabled': os.getenv('LLM_ENABLED', 'false').lower() == 'true',
        'provider': os.getenv('LLM_PROVIDER', 'auto'),
        'url': os.getenv('LLM_URL', 'http://ollama:11434'),
        'model': os.getenv('LLM_MODEL', 'mistral'),
        'api_key': os.getenv('LLM_API_KEY', ''),
        'generation_language': os.getenv('LLM_GENERATION_LANGUAGE', 'en'),
        'custom_prompt_ioc': '',
        'custom_prompt_case': '',
        'custom_prompt_incident': '',
        'custom_prompt_checklist': '',
        'configured': report_service.is_configured()
    })


@bp.route('/api/reports/available-models', methods=['POST'])
@login_required
def get_available_models():
    """
    Get available LLM models from server (Admin only)
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              default: "http://ollama:11434"
            provider:
              type: string
              default: "auto"
    responses:
      200:
        description: List of available models retrieved
        schema:
          type: object
          properties:
            models:
              type: array
              items:
                type: string
            success:
              type: boolean
      403:
        description: Admin access required
    """
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    llm_url = data.get('url', os.getenv('LLM_URL', 'http://ollama:11434')).rstrip('/')  # Remove trailing slashes
    provider = data.get('provider', os.getenv('LLM_PROVIDER', 'auto'))
    api_key = data.get('api_key', os.getenv('LLM_API_KEY', ''))
    
    try:
        import requests
        models = []
        
        
        # If provider is auto or not specified, try both
        if provider == 'auto' or provider == 'openai':
            # Try OpenAI-compatible endpoint first
            try:
                headers = {'Content-Type': 'application/json'}
                if api_key:
                    # Encode API key properly for HTTP headers
                    # Convert to string if bytes, then encode to UTF-8 bytes, then decode as latin-1
                    api_key_str = api_key if isinstance(api_key, str) else str(api_key)
                    try:
                        # Try to use the key as-is if it's ASCII
                        api_key_str.encode('ascii')
                        headers['Authorization'] = f'Bearer {api_key_str}'
                    except UnicodeEncodeError:
                        # If not ASCII, encode as UTF-8 bytes then decode as latin-1 for HTTP headers
                        api_key_latin1 = api_key_str.encode('utf-8').decode('latin-1')
                        headers['Authorization'] = f'Bearer {api_key_latin1}'
                
                test_url = f"{llm_url}/v1/models"
                response = requests.get(test_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    models_data = response.json()
                    
                    # Try multiple formats to extract models
                    if 'data' in models_data and isinstance(models_data['data'], list):
                        # Standard OpenAI format
                        models = [model.get('id', model.get('name', str(model))) for model in models_data['data']]
                    elif 'models' in models_data and isinstance(models_data['models'], list):
                        # Alternative format: {models: [...]}
                        models = [model.get('id', model.get('name', str(model))) for model in models_data['models']]
                    elif isinstance(models_data, list):
                        # Direct list of models
                        models = [m.get('id', m.get('name', str(m))) if isinstance(m, dict) else str(m) for m in models_data]
                    else:
                        # Try to extract from any 'id' or 'name' fields
                        models = []
                        for key, value in models_data.items():
                            if key not in ['object', 'usage', 'error']:
                                if isinstance(value, dict) and 'id' in value:
                                    models.append(value['id'])
                                elif isinstance(value, dict) and 'name' in value:
                                    models.append(value['name'])
                                elif isinstance(value, str):
                                    models.append(value)
                    
                    if models:
                        return jsonify({'models': models, 'success': True})
            except Exception as e:
                if provider == 'openai':
                    return jsonify({
                        'models': [],
                        'error': f'Could not fetch OpenAI models: {type(e).__name__}: {str(e)}',
                        'success': False
                    }), 200
        
        # If provider is auto or ollama, try Ollama endpoint
        if provider == 'auto' or provider == 'ollama':
            try:
                test_url = f"{llm_url}/api/tags"
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    models_data = response.json()
                    
                    # Extract model names from the response
                    models = []
                    if 'models' in models_data and isinstance(models_data['models'], list):
                        models = [model.get('name', model) for model in models_data['models'] if isinstance(model, dict)]
                    elif isinstance(models_data, dict) and 'models' in models_data:
                        # Alternative format
                        for key, value in models_data['models'].items():
                            if isinstance(value, dict) and 'name' in value:
                                models.append(value['name'])
                            else:
                                models.append(key)
                    
                    # Remove duplicates and sort
                    models = sorted(list(set(models)))
                    
                    return jsonify({'models': models, 'success': True})
                else:
                    return jsonify({'models': [], 'error': f'Server returned {response.status_code}', 'success': False}), 200
            except Exception as e:
                if provider == 'ollama':
                    return jsonify({
                        'models': [],
                        'error': f'Could not fetch Ollama models: {type(e).__name__}: {str(e)}',
                        'success': False
                    }), 200
        
        # If both endpoints failed
        return jsonify({
            'models': [],
            'error': 'Could not fetch models from any available endpoint',
            'success': False
        }), 200
    except Exception as e:
        return jsonify({
            'models': [],
            'error': f'Unexpected error: {str(e)}',
            'success': False
        }), 200


@bp.route('/api/reports/config', methods=['POST'])
@login_required
def update_report_config():
    """
    Update LLM configuration (Admin only)
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            enabled:
              type: boolean
            provider:
              type: string
              default: "auto"
            url:
              type: string
              default: "http://ollama:11434"
            model:
              type: string
              default: "mistral"
            api_key:
              type: string
            generation_language:
              type: string
              default: "en"
            custom_prompt_ioc:
              type: string
            custom_prompt_case:
              type: string
            custom_prompt_incident:
              type: string
            custom_prompt_checklist:
              type: string
    responses:
      200:
        description: Configuration updated successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
            configured:
              type: boolean
      403:
        description: Admin access required
    """
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    config = {
        'enabled': data.get('enabled', False),
        'provider': data.get('provider', 'auto'),
        'url': data.get('url', 'http://ollama:11434'),
        'model': data.get('model', 'mistral'),
        'api_key': data.get('api_key', ''),
        'generation_language': data.get('generation_language', 'en'),
        'custom_prompt_ioc': data.get('custom_prompt_ioc', ''),
        'custom_prompt_case': data.get('custom_prompt_case', ''),
        'custom_prompt_incident': data.get('custom_prompt_incident', ''),
        'custom_prompt_checklist': data.get('custom_prompt_checklist', ''),
        'configured': False  # Will be set after testing
    }
    
    # Update environment variables
    os.environ['LLM_URL'] = config['url']
    os.environ['LLM_MODEL'] = config['model']
    os.environ['LLM_API_KEY'] = config['api_key']
    os.environ['LLM_PROVIDER'] = config['provider']
    os.environ['LLM_ENABLED'] = 'true' if config['enabled'] else 'false'
    os.environ['LLM_GENERATION_LANGUAGE'] = config['generation_language']
    
    # Save to Elasticsearch for persistence
    try:
        es_service.index('elasmisp_app_config', 'llm_config', config)
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




@bp.route('/api/reports/iocs/<ioc_id>', methods=['GET'])
@login_required
@permission_required('report.generate_llm')
def generate_ioc_report(ioc_id):
    """
    Generate AI-powered analysis report for an IOC
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: ioc_id
        type: string
        required: true
        description: IOC identifier
    responses:
      200:
        description: Report generation started or completed
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
              enum: [pending, completed]
            message:
              type: string
      400:
        description: LLM reporting not enabled
      404:
        description: IOC not found
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_ioc_report as task_generate_ioc
        import time
        
        # Launch async task (Celery required)
        task = task_generate_ioc.delay(ioc_id, current_user.username)
        task_id = task.id
        
        # Wait briefly for completion (up to 5 seconds) instead of returning immediately
        # This allows synchronous-like behavior with async workers
        for attempt in range(50):  # 50 * 0.1 = 5 seconds
            try:
                response = es_service.get('elasmisp_app_config', f'report_{task_id}')
                if response and response.get('found'):
                    config = response.get('_source', {})
                    if config.get('status') == 'completed':
                        # Report is ready! Return it with completed status
                        return jsonify({
                            'task_id': task_id,
                            'status': 'completed',
                            'message': 'Report generation completed'
                        })
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # If not completed within 5 seconds, return pending status
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/cases/<case_id>', methods=['GET'])
@login_required
@permission_required('report.generate_llm')
def generate_case_report(case_id):
    """
    Generate AI-powered investigation summary for a case
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: case_id
        type: string
        required: true
        description: Case identifier
    responses:
      200:
        description: Report generation started or completed
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
              enum: [pending, completed]
            message:
              type: string
      400:
        description: LLM reporting not enabled
      404:
        description: Case not found
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_case_report as task_generate_case
        import time
        
        # Launch async task (Celery required)
        task = task_generate_case.delay(case_id, current_user.username)
        task_id = task.id
        
        # Wait briefly for completion (up to 5 seconds) instead of returning immediately
        # This allows synchronous-like behavior with async workers
        for attempt in range(50):  # 50 * 0.1 = 5 seconds
            try:
                response = es_service.get('elasmisp_app_config', f'report_{task_id}')
                if response and response.get('found'):
                    config = response.get('_source', {})
                    if config.get('status') == 'completed':
                        # Report is ready! Return it with completed status
                        return jsonify({
                            'task_id': task_id,
                            'status': 'completed',
                            'message': 'Report generation completed'
                        })
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # If not completed within 5 seconds, return pending status
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/incidents/<incident_id>', methods=['GET'])
@login_required
@permission_required('report.generate_llm')
def generate_incident_report(incident_id):
    """
    Generate AI-powered incident analysis report
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: incident_id
        type: string
        required: true
        description: Incident identifier
    responses:
      200:
        description: Report generation started or completed
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
              enum: [pending, completed]
            message:
              type: string
      400:
        description: LLM reporting not enabled
      404:
        description: Incident not found
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_incident_report as task_generate_incident
        import time
        
        # Launch async task (Celery required)
        task = task_generate_incident.delay(incident_id, current_user.username)
        task_id = task.id
        
        # Wait briefly for completion (up to 5 seconds) instead of returning immediately
        # This allows synchronous-like behavior with async workers
        for attempt in range(50):  # 50 * 0.1 = 5 seconds
            try:
                response = es_service.get('elasmisp_app_config', f'report_{task_id}')
                if response and response.get('found'):
                    config = response.get('_source', {})
                    if config.get('status') == 'completed':
                        # Report is ready! Return it with completed status
                        return jsonify({
                            'task_id': task_id,
                            'status': 'completed',
                            'message': 'Report generation completed'
                        })
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # If not completed within 5 seconds, return pending status
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/checklists/<checklist_id>', methods=['GET'])
@login_required
@permission_required('checklist.generate_llm')
def generate_checklist_report(checklist_id):
    """
    Generate AI-powered checklist analysis report
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: checklist_id
        type: string
        required: true
        description: Checklist identifier
    responses:
      200:
        description: Report generation started or completed
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
              enum: [pending, completed]
            message:
              type: string
      400:
        description: LLM reporting not enabled
      404:
        description: Checklist not found
    """
    if not os.getenv('LLM_ENABLED', 'false').lower() == 'true':
        return jsonify({'error': 'LLM reporting not enabled'}), 400
    
    try:
        from app.tasks.report_tasks import generate_checklist_report as task_generate_checklist
        import time
        
        # Launch async task (Celery required)
        task = task_generate_checklist.delay(checklist_id, current_user.username)
        task_id = task.id
        
        # Wait briefly for completion (up to 5 seconds) instead of returning immediately
        # This allows synchronous-like behavior with async workers
        for attempt in range(50):  # 50 * 0.1 = 5 seconds
            try:
                response = es_service.get('elasmisp_app_config', f'report_{task_id}')
                if response and response.get('found'):
                    config = response.get('_source', {})
                    if config.get('status') == 'completed':
                        # Report is ready! Return it with completed status
                        return jsonify({
                            'task_id': task_id,
                            'status': 'completed',
                            'message': 'Report generation completed'
                        })
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # If not completed within 5 seconds, return pending status
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'message': 'Report generation started'
        })
    except Exception as e:
        import sys
        print(f"DEBUG: Error in generate_checklist_report: {str(e)}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/status/<task_id>', methods=['GET'])
@login_required
def get_report_status(task_id):
    """
    Check report generation task status
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: task_id
        type: string
        required: true
        description: Report task identifier
    responses:
      200:
        description: Report status
        schema:
          type: object
          properties:
            status:
              type: string
              enum: [pending, started, success, failure]
            progress:
              type: number
            report:
              type: object
      404:
        description: Report not found
      403:
        description: Access denied
    """
    try:
        response = es_service.get('elasmisp_app_config', f'report_{task_id}')
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
    """
    List all generated reports with pagination and filtering
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: query
        name: page
        type: integer
        default: 1
      - in: query
        name: per_page
        type: integer
        default: 20
      - in: query
        name: entity_type
        type: string
        description: Filter by entity type (ioc, case, incident, checklist)
      - in: query
        name: sort
        type: string
        default: created_at
      - in: query
        name: order
        type: string
        enum: [asc, desc]
        default: desc
    responses:
      200:
        description: List of reports
        schema:
          type: object
          properties:
            total:
              type: integer
            page:
              type: integer
            per_page:
              type: integer
            reports:
              type: array
              items:
                type: object
    """
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
        
        result = es_service.search('elasmisp_app_config', query)
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
    """
    Get report content for viewing
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: task_id
        type: string
        required: true
        description: Report task identifier
    responses:
      200:
        description: Report content
        schema:
          type: object
          properties:
            task_id:
              type: string
            status:
              type: string
            content:
              type: string
            created_at:
              type: string
      404:
        description: Report not found
      403:
        description: Access denied
    """
    try:
        response = es_service.get('elasmisp_app_config', f'report_{task_id}')
        if not response or not response.get('found'):
            return jsonify({'error': 'Report not found', 'status': 'error'}), 404
        
        config = response.get('_source', {})
        
        # Check if user has permission to view this report
        if config.get('user_id') != current_user.username and not current_user.is_admin:
            return jsonify({'error': 'Access denied', 'status': 'error'}), 403
        
        status = config.get('status')
        if status == 'error' or status == 'failed':
            # Return error details
            error_reason = config.get('error', 'Unknown error occurred')
            return jsonify({
                'error': error_reason,
                'status': 'error',
                'task_id': task_id,
                'error_details': {
                    'timestamp': config.get('completed_at', 'Unknown'),
                    'full_message': error_reason
                }
            }), 200
        
        if status != 'completed':
            return jsonify({
                'error': f'Report not yet completed (status: {status})',
                'status': status,
                'task_id': task_id
            }), 202  # 202 Accepted - request received but not completed yet
        
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
        return jsonify({'error': str(e), 'status': 'error'}), 500

@bp.route('/api/reports/<task_id>', methods=['DELETE'])
@login_required
def delete_report(task_id):
    """
    Delete a generated report
    ---
    tags:
      - Reports
    security:
      - Bearer: []
    parameters:
      - in: path
        name: task_id
        type: string
        required: true
        description: Report task identifier
    responses:
      200:
        description: Report deleted successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      404:
        description: Report not found
      403:
        description: Access denied
    """
    try:
        from app.services.audit_service import AuditService
        audit = AuditService()
        
        response = es_service.get('elasmisp_app_config', f'report_{task_id}')
        if not response or not response.get('found'):
            return jsonify({'error': 'Report not found'}), 404
        
        config = response.get('_source', {})
        
        # Check if user has permission to delete this report
        if config.get('user_id') != current_user.username and not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403
        
        # Delete the report from Elasticsearch
        es_service.delete('elasmisp_app_config', f'report_{task_id}')
        
        # Log the deletion
        audit.log(
            action='report_deleted',
            entity_type=config.get('type', 'unknown'),
            entity_id=config.get('entity_id', task_id),
            username=current_user.username,
            entity_name=config.get('entity_name', f'Report {task_id}'),
            changes={'task_id': task_id}
        )
        
        return jsonify({'success': True, 'message': 'Report deleted successfully'})
    except Exception as e:
        import sys, traceback
        print(f"DEBUG: Exception in delete_report: {str(e)}", file=sys.stderr)
        print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500