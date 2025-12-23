"""Role-Based Access Control (RBAC) Service."""

from datetime import datetime
from typing import Dict, List, Optional
import secrets

from app.services.elasticsearch_service import ElasticsearchService


# Permission definitions
PERMISSIONS = {
    # IOC permissions
    'ioc.view': 'View IOCs',
    'ioc.create': 'Create IOCs',
    'ioc.edit': 'Edit IOCs',
    'ioc.delete': 'Delete IOCs',
    'ioc.export': 'Export IOCs',
    'ioc.import': 'Import IOCs',
    'ioc.enrich': 'Enrich IOCs with external APIs',
    
    # Case permissions
    'case.view': 'View cases',
    'case.create': 'Create cases',
    'case.edit': 'Edit cases',
    'case.delete': 'Delete cases',
    'case.assign': 'Assign cases to users',
    
    # Incident permissions
    'incident.view': 'View incidents',
    'incident.create': 'Create incidents',
    'incident.edit': 'Edit incidents',
    'incident.delete': 'Delete incidents',
    'incident.report': 'Generate incident reports',
    
    # Comment permissions
    'comment.view': 'View comments',
    'comment.create': 'Create comments',
    'comment.edit': 'Edit own comments',
    'comment.delete': 'Delete comments',
    'comment.edit_any': 'Edit any comment',
    
    # Snippet permissions
    'snippet.view': 'View snippets',
    'snippet.create': 'Create snippets',
    'snippet.edit': 'Edit own snippets',
    'snippet.delete': 'Delete own snippets',
    'snippet.manage_global': 'Manage global snippets',
    
    # Timeline permissions
    'timeline.view': 'View timeline',
    'timeline.create': 'Create timeline events',
    'timeline.edit': 'Edit timeline events',
    'timeline.delete': 'Delete timeline events',
    
    # API permissions
    'api.access': 'Access API',
    'api.keys.manage': 'Manage API keys',
    'api.external.configure': 'Configure external APIs',
    
    # Webhook permissions
    'webhook.view': 'View webhooks',
    'webhook.manage': 'Manage webhooks',
    
    # Admin permissions
    'admin.users': 'Manage users',
    'admin.roles': 'Manage roles',
    'admin.settings': 'Manage site settings',
    'admin.audit': 'View audit logs',
    'admin.tasks': 'Manage scheduled tasks',
}


# Default role definitions
DEFAULT_ROLES = {
    'admin': {
        'display_name': 'Administrator',
        'description': 'Full system access with all permissions',
        'permissions': list(PERMISSIONS.keys()),
        'is_system': True
    },
    'analyst': {
        'display_name': 'Security Analyst',
        'description': 'Can manage IOCs, cases, incidents and reports',
        'permissions': [
            'ioc.view', 'ioc.create', 'ioc.edit', 'ioc.export', 'ioc.import', 'ioc.enrich',
            'case.view', 'case.create', 'case.edit', 'case.assign',
            'incident.view', 'incident.create', 'incident.edit', 'incident.report',
            'comment.view', 'comment.create', 'comment.edit',
            'snippet.view', 'snippet.create', 'snippet.edit',
            'timeline.view', 'timeline.create', 'timeline.edit',
            'api.access', 'api.keys.manage',
            'webhook.view',
        ],
        'is_system': True
    },
    'viewer': {
        'display_name': 'Viewer',
        'description': 'Read-only access to IOCs and cases',
        'permissions': [
            'ioc.view', 'ioc.export',
            'case.view',
            'incident.view',
            'comment.view', 'comment.create',
            'snippet.view',
            'timeline.view',
            'api.access',
        ],
        'is_system': True
    }
}


class RBACService:
    """Service for Role-Based Access Control."""
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def init_default_roles(self):
        """Initialize default system roles if they don't exist."""
        for role_name, role_data in DEFAULT_ROLES.items():
            existing = self.get_role(role_name)
            if not existing:
                self.create_role(
                    name=role_name,
                    display_name=role_data['display_name'],
                    description=role_data['description'],
                    permissions=role_data['permissions'],
                    is_system=role_data['is_system']
                )
    
    def create_role(self, name: str, display_name: str, description: str,
                    permissions: List[str], is_system: bool = False) -> Dict:
        """Create a new role."""
        role_doc = {
            'id': name,
            'name': name,
            'display_name': display_name,
            'description': description,
            'permissions': permissions,
            'is_system': is_system,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('roles', name, role_doc)
        return role_doc
    
    def get_role(self, role_name: str) -> Optional[Dict]:
        """Get a role by name."""
        try:
            result = self.es.get('roles', role_name)
            if result:
                return result['_source']
        except Exception:
            pass
        return None
    
    def get_all_roles(self) -> List[Dict]:
        """Get all roles."""
        result = self.es.search('roles', {
            'query': {'match_all': {}},
            'size': 100
        })
        
        roles = []
        for hit in result['hits']['hits']:
            role = hit['_source']
            role['id'] = hit['_id']
            roles.append(role)
        return roles
    
    def update_role(self, role_name: str, updates: Dict) -> Optional[Dict]:
        """Update a role."""
        role = self.get_role(role_name)
        if not role:
            return None
        
        # Don't allow updating system role names
        if role.get('is_system') and 'name' in updates:
            del updates['name']
        
        updates['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.es.update('roles', role_name, {'doc': updates})
        return self.get_role(role_name)
    
    def delete_role(self, role_name: str) -> bool:
        """Delete a role (only custom roles)."""
        role = self.get_role(role_name)
        if not role or role.get('is_system'):
            return False
        
        self.es.delete('roles', role_name)
        return True
    
    def get_user_permissions(self, user) -> List[str]:
        """Get all permissions for a user based on their role."""
        # Legacy admin check
        if getattr(user, 'is_admin', False):
            return list(PERMISSIONS.keys())
        
        role_name = getattr(user, 'role', 'viewer')
        role = self.get_role(role_name)
        
        if role:
            return role.get('permissions', [])
        
        # Default to viewer permissions if role not found
        return DEFAULT_ROLES['viewer']['permissions']
    
    def user_has_permission(self, user, permission: str) -> bool:
        """Check if user has a specific permission."""
        permissions = self.get_user_permissions(user)
        return permission in permissions
    
    def user_has_any_permission(self, user, permissions: List[str]) -> bool:
        """Check if user has any of the specified permissions."""
        user_perms = self.get_user_permissions(user)
        return any(p in user_perms for p in permissions)
    
    def user_has_all_permissions(self, user, permissions: List[str]) -> bool:
        """Check if user has all of the specified permissions."""
        user_perms = self.get_user_permissions(user)
        return all(p in user_perms for p in permissions)
    
    @staticmethod
    def get_all_permissions() -> Dict[str, str]:
        """Get all available permissions."""
        return PERMISSIONS.copy()
    
    @staticmethod
    def get_permissions_by_category() -> Dict[str, Dict[str, str]]:
        """Get permissions grouped by category."""
        categories = {}
        for perm, desc in PERMISSIONS.items():
            category = perm.split('.')[0]
            if category not in categories:
                categories[category] = {}
            categories[category][perm] = desc
        return categories
