"""Role-Based Access Control (RBAC) Service."""

from datetime import datetime
from typing import Dict, List, Optional
import secrets

from app.services.elasticsearch_service import ElasticsearchService


# Permission definitions - Organized by category
# IMPORTANT: Only include permissions that are actually checked in the application
PERMISSIONS = {
    # ============== IOC Management ==============
    'ioc.view': 'View IOCs',
    'ioc.create': 'Create IOCs',
    'ioc.edit': 'Edit IOCs',
    'ioc.delete': 'Delete IOCs',
    'ioc.export': 'Export IOCs',
    'ioc.import': 'Import IOCs',
    'ioc.enrich': 'Enrich IOCs with external APIs',
    'ioc.relations.view': 'View IOC relationships',
    'ioc.relations.create': 'Create IOC relationships',
    'ioc.relations.delete': 'Delete IOC relationships',
    
    # ============== Case Management ==============
    'case.view': 'View cases',
    'case.create': 'Create cases',
    'case.edit': 'Edit cases',
    'case.delete': 'Delete cases',
    'case.assign': 'Assign cases to users',
    'case.close': 'Close cases',
    
    # ============== Incident Management ==============
    'incident.view': 'View incidents',
    'incident.create': 'Create incidents',
    'incident.edit': 'Edit incidents',
    'incident.delete': 'Delete incidents',
    'incident.report': 'Generate incident reports',
    
    # ============== Comments & Collaboration ==============
    'comment.view': 'View comments',
    'comment.create': 'Create comments',
    'comment.edit': 'Edit own comments',
    'comment.delete': 'Delete own comments',
    'comment.edit_any': 'Edit any comment',
    'comment.delete_any': 'Delete any comment',
    
    # ============== Snippets & Templates ==============
    'snippet.view': 'View snippets',
    'snippet.create': 'Create snippets',
    'snippet.edit': 'Edit own snippets',
    'snippet.delete': 'Delete own snippets',
    'snippet.share': 'Share snippets',
    
    # ============== Timeline Management ==============
    'timeline.view': 'View timeline and audit logs',
    'timeline.export': 'Export timeline data',
    
    # ============== API & Integration ==============
    'api.access': 'Access API',
    'api.keys.view': 'View API keys',
    'api.keys.create': 'Create API keys',
    'api.keys.delete': 'Delete API keys',
    'api.external.view': 'View external API configurations',
    'api.external.create': 'Create external API configurations',
    'api.external.edit': 'Edit external API configurations',
    'api.external.delete': 'Delete external API configurations',
    'api.external.test': 'Test external APIs',
    
    # ============== Webhook Management ==============
    'webhook.view': 'View webhooks',
    'webhook.create': 'Create webhooks',
    'webhook.edit': 'Edit webhooks',
    'webhook.delete': 'Delete webhooks',
    'webhook.test': 'Test webhooks',
    
    # ============== Search & Reports ==============
    'search.advanced': 'Access advanced search',
    'search.save': 'Save searches',
    'report.view': 'View reports',
    'report.create': 'Create reports',
    'report.edit': 'Edit reports',
    'report.delete': 'Delete reports',
    'report.export': 'Export reports',
    'report.generate_llm': 'Generate reports using LLM',
    
    # ============== Checklists ==============
    'checklist.view': 'View checklists',
    'checklist.create': 'Create checklists',
    'checklist.edit': 'Edit checklists and items',
    'checklist.delete': 'Delete checklists',
    'checklist.export': 'Export checklists as Markdown',
    'checklist.generate_llm': 'Generate checklist reports using LLM',
    'checklist.comment.create': 'Add comments to checklist items',
    'checklist.comment.delete': 'Delete own comments on checklist items',
    'checklist.comment.delete_any': 'Delete any comments on checklist items',
    
    # ============== Checklist Templates ==============
    'checklist.template.view': 'View checklist templates',
    'checklist.template.create': 'Create checklist templates',
    'checklist.template.edit': 'Edit checklist templates',
    'checklist.template.delete': 'Delete checklist templates',
    'checklist.template.use': 'Use templates to create checklists',
    
    # ============== Tools & Enrichment ==============
    'tools.view': 'View tool results',
    'tools.execute': 'Execute analysis tools',
    'tools.configure': 'Configure tools',
    
    # ============== Administration ==============
    'admin.users.view': 'View users',
    'admin.users.create': 'Create users',
    'admin.users.edit': 'Edit users',
    'admin.users.delete': 'Delete users',
    'admin.users.assign_role': 'Assign roles to users',
    'admin.roles.view': 'View roles',
    'admin.roles.create': 'Create custom roles',
    'admin.roles.edit': 'Edit roles',
    'admin.roles.delete': 'Delete custom roles',
    'admin.roles.manage': 'Manage all roles',
    'admin.settings': 'Manage site settings',
    'admin.settings.view': 'View site settings',
    'admin.settings.edit': 'Edit site settings',
    'admin.audit': 'View audit logs',
    'admin.tasks': 'Manage scheduled tasks',
    'admin.tasks.execute': 'Execute scheduled tasks',
    'admin.tasks.config': 'Configure scheduled tasks',
    'admin.tasks.history': 'View task history',
    'admin.tasks.manage': 'Manage all scheduled tasks',
    'admin.llm.manage': 'Manage LLM settings and reports',
    'admin.elasticsearch.stats': 'View Elasticsearch statistics',
}


# Default role definitions with granular permissions
DEFAULT_ROLES = {
    'admin': {
        'display_name': 'Administrator',
        'description': 'Full system access - can manage all resources and users',
        'color': '#dc3545',  # Red
        'permissions': list(PERMISSIONS.keys()),
        'is_system': True,
        'is_editable': False
    },
    'analyst': {
        'display_name': 'Security Analyst',
        'description': 'Can manage IOCs, cases, incidents and create reports',
        'color': '#0066cc',  # Blue
        'permissions': [
            # IOC permissions
            'ioc.view', 'ioc.create', 'ioc.edit', 'ioc.export', 'ioc.import', 'ioc.enrich',
            'ioc.relations.view', 'ioc.relations.create', 'ioc.relations.delete',
            # Case permissions
            'case.view', 'case.create', 'case.edit', 'case.assign', 'case.close',
            # Incident permissions
            'incident.view', 'incident.create', 'incident.edit', 'incident.report',
            # Comments & collaboration
            'comment.view', 'comment.create', 'comment.edit', 'comment.delete_any',
            'snippet.view', 'snippet.create', 'snippet.edit', 'snippet.share',
            # Timeline
            'timeline.view', 'timeline.export',
            # API
            'api.access', 'api.keys.view', 'api.keys.create', 'api.keys.delete',
            'api.external.view', 'api.external.create', 'api.external.edit', 'api.external.delete', 'api.external.test',
            'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.delete', 'webhook.test',
            # Tools
            'tools.view', 'tools.execute', 'tools.configure',
            # Search & Reports
            'search.advanced', 'search.save', 'report.view', 'report.create', 'report.export', 'report.generate_llm',
            # Checklists
            'checklist.view', 'checklist.create', 'checklist.edit', 'checklist.delete', 'checklist.export', 'checklist.generate_llm',
            'checklist.comment.create', 'checklist.comment.delete', 'checklist.comment.delete_any',
            'checklist.template.view', 'checklist.template.create', 'checklist.template.edit', 'checklist.template.delete', 'checklist.template.use',
            # Admin
            'admin.audit',
        ],
        'is_system': True,
        'is_editable': False
    },
    'threat_intel': {
        'display_name': 'Threat Intelligence Officer',
        'description': 'Specialized in threat intelligence, campaigns, and enrichment',
        'color': '#ff6600',  # Orange
        'permissions': [
            # IOC permissions
            'ioc.view', 'ioc.create', 'ioc.edit', 'ioc.export', 'ioc.import', 'ioc.enrich',
            'ioc.relations.view', 'ioc.relations.create',
            # Case & Incident - read mostly
            'case.view', 'incident.view',
            # Comments & collaboration
            'comment.view', 'comment.create', 'comment.edit',
            'snippet.view', 'snippet.create', 'snippet.edit', 'snippet.share',
            # Timeline
            'timeline.view', 'timeline.export',
            # API
            'api.access', 'api.keys.view', 'api.keys.create',
            'api.external.view', 'api.external.create', 'api.external.edit', 'api.external.test',
            'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.test',
            # Tools
            'tools.view', 'tools.execute',
            # Search & Reports
            'search.advanced', 'search.save', 'report.view', 'report.create', 'report.export', 'report.generate_llm',
            # Checklists
            'checklist.view', 'checklist.create', 'checklist.edit', 'checklist.delete', 'checklist.export', 'checklist.generate_llm',
            'checklist.comment.create', 'checklist.comment.delete', 'checklist.comment.delete_any',
            'checklist.template.view', 'checklist.template.create', 'checklist.template.edit', 'checklist.template.delete', 'checklist.template.use',
            # Admin
            'admin.audit',
        ],
        'is_system': True,
        'is_editable': False
    },
    'incident_responder': {
        'display_name': 'Incident Responder',
        'description': 'Focused on incident response, containment, and remediation',
        'color': '#cc0000',  # Dark red
        'permissions': [
            # IOC permissions
            'ioc.view', 'ioc.create', 'ioc.edit',
            'ioc.relations.view', 'ioc.relations.create',
            # Case & Incident
            'case.view', 'case.create', 'case.edit', 'case.assign', 'case.close',
            'incident.view', 'incident.create', 'incident.edit', 'incident.report',
            # Comments & collaboration
            'comment.view', 'comment.create', 'comment.edit', 'comment.delete_any',
            # Timeline
            'timeline.view', 'timeline.export',
            # API
            'api.access', 'api.keys.view', 'api.keys.create',
            'api.external.view', 'api.external.create', 'api.external.edit', 'api.external.delete', 'api.external.test',
            'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.delete', 'webhook.test',
            # Tools
            'tools.view', 'tools.execute',
            # Search & Reports
            'search.advanced', 'search.save', 'report.view', 'report.create', 'report.export', 'report.generate_llm',
            # Checklists
            'checklist.view', 'checklist.create', 'checklist.edit', 'checklist.delete', 'checklist.export', 'checklist.generate_llm',
            'checklist.comment.create', 'checklist.comment.delete', 'checklist.comment.delete_any',
            'checklist.template.view', 'checklist.template.create', 'checklist.template.edit', 'checklist.template.delete', 'checklist.template.use',
            # Admin
            'admin.audit',
        ],
        'is_system': True,
        'is_editable': False
    },

    'viewer': {
        'display_name': 'Viewer',
        'description': 'Read-only access to IOCs and cases',
        'color': '#666666',  # Gray
        'permissions': [
            # IOC - view only
            'ioc.view', 'ioc.export',
            'ioc.relations.view',
            # Case & Incident - view only
            'case.view',
            'incident.view',
            # Comments & collaboration - view & create
            'comment.view', 'comment.create',
            # Timeline
            'timeline.view',
            # API
            'api.access', 'api.keys.view',
            # Search & Reports
            'search.advanced', 'report.view', 'report.export',
            # Checklists
            'checklist.view', 'checklist.comment.create',
            'checklist.template.view', 'checklist.template.use',
        ],
        'is_system': True,
        'is_editable': False
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
