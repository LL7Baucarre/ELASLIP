from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user

from app.auth import APIKey

api_keys_bp = Blueprint('api_keys', __name__)


@api_keys_bp.route('', methods=['GET'])
@login_required
def list_keys():
    """List all API keys for current user."""
    keys = APIKey.get_by_user(current_user.id)
    
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'api_keys': [key.to_dict() for key in keys]
        })
    
    return render_template('settings/api_keys.html', keys=keys)


@api_keys_bp.route('', methods=['POST'])
@login_required
def create_key():
    """Create a new API key."""
    if request.is_json:
        data = request.get_json()
        label = data.get('label', 'Unnamed Key')
    else:
        label = request.form.get('label', 'Unnamed Key')
    
    if not label:
        label = 'Unnamed Key'
    
    key, key_obj = APIKey.create(current_user.id, label)
    
    response_data = {
        'message': 'API key created successfully',
        'api_key': key,  # Only returned once!
        'key_info': key_obj.to_dict()
    }
    
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify(response_data), 201
    
    return render_template('settings/api_key_created.html', 
                          key=key, 
                          key_info=key_obj.to_dict())


@api_keys_bp.route('/<key_id>', methods=['DELETE'])
@login_required
def revoke_key(key_id):
    """Revoke an API key."""
    success = APIKey.revoke(key_id, current_user.id)
    
    if not success:
        return jsonify({'error': 'Key not found or not authorized'}), 404
    
    return jsonify({'message': 'API key revoked successfully'})
