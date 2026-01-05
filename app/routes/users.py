"""User API routes for user search and management."""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user

from app.services.elasticsearch_service import ElasticsearchService
from app.decorators import permission_required

users_bp = Blueprint('users', __name__)


@users_bp.route('/search')
@login_required
@permission_required('search.users')
def search_users():
    """
    Search users for assignment (autocomplete).
    
    This endpoint allows any authenticated user to search for users
    to assign to cases, incidents, or checklists. Returns limited user info
    (id, username, email) for privacy.
    
    Query params:
        q: Search query (searches username and email)
        limit: Max results (default 10, max 50)
    
    Returns:
        JSON list of matching users
    """
    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 10)), 50)
    
    es = ElasticsearchService()
    
    if not query or len(query) < 2:
        return jsonify({'users': [], 'total': 0})
    
    # Search users by username or email using wildcard
    search_query = {
        "bool": {
            "should": [
                {
                    "wildcard": {
                        "username": {
                            "value": f"*{query.lower()}*",
                            "case_insensitive": True
                        }
                    }
                },
                {
                    "wildcard": {
                        "email": {
                            "value": f"*{query.lower()}*",
                            "case_insensitive": True
                        }
                    }
                }
            ],
            "minimum_should_match": 1
        }
    }
    
    try:
        result = es.search('users', {
            'query': search_query,
            'size': limit,
            '_source': ['username', 'email', 'role'],
            'sort': [{'username.keyword': {'order': 'asc'}}]
        })
        
        users = []
        for hit in result['hits']['hits']:
            user = hit['_source']
            user['id'] = hit['_id']
            users.append({
                'id': user['id'],
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'role': user.get('role', 'viewer')
            })
        
        return jsonify({
            'users': users,
            'total': result['hits']['total']['value']
        })
    except Exception as e:
        current_app.logger.error(f"User search error: {str(e)}")
        return jsonify({'users': [], 'total': 0, 'error': str(e)}), 500
