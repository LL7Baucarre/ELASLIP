"""Import API Routes."""

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
    Create a new import job.
    
    Expected form data or JSON:
    - file: The file to import (form-data)
    - content: File content as string (JSON)
    - type: File type (stix, misp, openioc, iodef)
    """
    es = ElasticsearchService()
    
    # Get file type
    file_type = request.form.get('type') or request.args.get('type')
    
    if request.is_json:
        data = request.get_json()
        file_content = data.get('content')
        file_type = file_type or data.get('type')
        filename = data.get('filename', 'uploaded_file')
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
    
    if not file_type:
        # Try to detect from filename first
        file_type = detect_file_type(filename)
        
        # If we still don't have a type and it's JSON, analyze the content
        if not file_type and filename.lower().endswith('.json'):
            file_type = detect_json_file_type(file_content)
        
        # If we still don't have a type and it's XML, analyze the content
        if not file_type and filename.lower().endswith('.xml'):
            file_type = detect_xml_file_type(file_content)
    
    if not file_type:
        return jsonify({
            'error': 'File type not specified or could not be detected',
            'supported_types': ['stix', 'misp', 'openioc', 'iodef'],
            'hint': 'Please specify file type explicitly or use a filename that contains the type (e.g., event.misp.json, indicators.iodef.xml)'
        }), 400
    
    file_type = file_type.lower()
    if file_type not in ['stix', 'misp', 'openioc', 'iodef']:
        return jsonify({
            'error': f'Unsupported file type: {file_type}',
            'supported_types': ['stix', 'misp', 'openioc', 'iodef']
        }), 400
    
    # Create import job
    job_id = secrets.token_hex(16)
    job_data = {
        'id': job_id,
        'user_id': g.current_user.id,
        'filename': filename,
        'file_type': file_type,
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
    process_import.delay(job_id, file_content, file_type, g.current_user.id)
    
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


def detect_file_type(filename: str) -> str:
    """Detect file type from filename with better heuristics."""
    filename = filename.lower()
    
    if 'stix' in filename:
        return 'stix'
    elif 'misp' in filename:
        return 'misp'
    elif 'openioc' in filename or filename.endswith('.ioc'):
        return 'openioc'
    elif 'iodef' in filename:
        return 'iodef'
    # For .json files, don't assume type - let caller analyze content
    elif filename.endswith('.json'):
        return None
    # Don't assume XML type - let caller specify or analyze content
    elif filename.endswith('.xml'):
        return None
    
    return None


def detect_json_file_type(content: str) -> str:
    """
    Detect JSON file type by analyzing structure.
    
    Args:
        content: JSON file content
    
    Returns:
        'misp', 'stix', or None if type cannot be determined
    """
    try:
        import json
        data = json.loads(content)
        
        # Check for MISP structure
        if 'Event' in data:
            return 'misp'
        
        # Check for STIX structure
        if isinstance(data, dict):
            if data.get('type') in ['bundle', 'indicator']:
                return 'stix'
            if 'spec_version' in data and '2.' in str(data.get('spec_version', '')):
                return 'stix'
        
    except (json.JSONDecodeError, TypeError):
        pass
    
    return None


def detect_xml_file_type(content: str) -> str:
    """
    Detect XML file type by analyzing root element and namespaces.
    
    Args:
        content: XML file content
    
    Returns:
        'iodef', 'openioc', or None if type cannot be determined
    """
    try:
        from lxml import etree
        root = etree.fromstring(content.encode('utf-8'))
        
        # Check namespaces
        ns = root.nsmap.get(None, '')
        if 'iodef' in ns.lower():
            return 'iodef'
        elif 'ioc' in ns.lower() and 'mandiant' in ns.lower():
            return 'openioc'
        
        # Check root tag name
        tag = root.tag.split('}')[-1].lower()
        if 'incident' in tag:
            return 'iodef'
        elif 'ioc' in tag:
            return 'openioc'
    except Exception:
        pass
    
    return None

