"""Import API Routes - STIX 2.1 Only."""

import secrets
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app.auth import login_or_api_key_required
from app.decorators import permission_required
from app.services.elasticsearch_service import ElasticsearchService
from app.tasks.import_tasks import process_import

import_bp = Blueprint('import', __name__)


@import_bp.route('', methods=['POST'])
@login_or_api_key_required
@permission_required('ioc.import')
def create_import():
    """
    Create a new STIX import job.
    
    Expected form data or JSON:
    - file: The STIX JSON file to import (form-data)
    - content: File content as string (JSON)
    """
    es = ElasticsearchService()
    
    if request.is_json:
        data = request.get_json()
        file_content = data.get('content')
        filename = data.get('filename', 'uploaded_file.json')
    else:
        # Handle file upload
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = file.filename
        file_content = file.read().decode('utf-8')
    
    if not file_content:
        return jsonify({'error': 'Empty file content'}), 400
    
    # Validate it's a valid STIX JSON
    if not is_valid_stix(file_content):
        return jsonify({
            'error': 'Invalid STIX format',
            'hint': 'File must be a valid STIX 2.1 JSON bundle or object'
        }), 400
    
    # Create import job
    job_id = secrets.token_hex(16)
    job_data = {
        'id': job_id,
        'user_id': g.current_user.id,
        'filename': filename,
        'file_type': 'stix',
        'status': 'pending',
        'progress': 0,
        'total_items': 0,
        'processed_items': 0,
        'added': 0,
        'updated': 0,
        'duplicates': 0,
        'errors': 0,
        'error_details': [],
        'started_at': datetime.utcnow().isoformat(),
        'completed_at': None
    }
    
    es.index('import_jobs', job_id, job_data)
    
    # Queue the import task
    process_import.delay(job_id, file_content, 'stix', g.current_user.id)
    
    return jsonify({
        'message': 'Import job created',
        'job_id': job_id,
        'status': 'pending'
    }), 202


@import_bp.route('/<job_id>', methods=['GET'])
@login_or_api_key_required
def get_import_status(job_id):
    """Get the status of an import job."""
    es = ElasticsearchService()
    
    result = es.get('import_jobs', job_id)
    
    if not result:
        return jsonify({'error': 'Import job not found'}), 404
    
    job = result['_source']
    
    # Check ownership
    if job['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    return jsonify(job)


@import_bp.route('', methods=['GET'])
@login_or_api_key_required
@permission_required('ioc.import')
def list_imports():
    """List import jobs for current user."""
    es = ElasticsearchService()
    
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status = request.args.get('status')
    
    query = {'bool': {'must': [
        {'term': {'user_id': g.current_user.id}}
    ]}}
    
    if status:
        query['bool']['must'].append({'term': {'status': status}})
    
    from_idx = (page - 1) * per_page
    
    result = es.search('import_jobs', {
        'query': query,
        'from': from_idx,
        'size': per_page,
        'sort': [{'started_at': {'order': 'desc'}}]
    })
    
    jobs = []
    for hit in result['hits']['hits']:
        job = hit['_source']
        job['id'] = hit['_id']
        jobs.append(job)
    
    return jsonify({
        'jobs': jobs,
        'total': result['hits']['total']['value'],
        'page': page,
        'per_page': per_page
    })


@import_bp.route('/<job_id>', methods=['DELETE'])
@login_or_api_key_required
@permission_required('ioc.import')
def delete_import(job_id):
    """Delete an import job record."""
    es = ElasticsearchService()
    
    result = es.get('import_jobs', job_id)
    
    if not result:
        return jsonify({'error': 'Import job not found'}), 404
    
    job = result['_source']
    
    # Check ownership
    if job['user_id'] != g.current_user.id:
        return jsonify({'error': 'Not authorized'}), 403
    
    es.delete('import_jobs', job_id)
    
    return jsonify({'message': 'Import job deleted'})


def is_valid_stix(content: str) -> bool:
    """
    Validate that content is valid STIX 2.1 JSON.
    
    Args:
        content: JSON file content
    
    Returns:
        True if valid STIX, False otherwise
    """
    try:
        import json
        data = json.loads(content)
        
        if not isinstance(data, dict):
            return False
        
        # Check for STIX bundle
        if data.get('type') == 'bundle':
            return 'objects' in data or 'spec_version' in data
        
        # Check for single STIX object
        if data.get('type') in ['indicator', 'malware', 'threat-actor', 'campaign', 
                                 'attack-pattern', 'tool', 'vulnerability', 'infrastructure',
                                 'intrusion-set', 'identity', 'location', 'course-of-action',
                                 'relationship', 'sighting', 'observed-data', 'report',
                                 'grouping', 'note', 'opinion', 'malware-analysis']:
            return True
        
        # Check for spec_version indicating STIX 2.x
        if 'spec_version' in data and '2.' in str(data.get('spec_version', '')):
            return True
        
        return False
        
    except (json.JSONDecodeError, TypeError):
        return False

