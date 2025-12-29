"""
RBAC Permission Matrix - Defines granular permissions for each role.

This file defines a comprehensive permission matrix for role-based access control.
Each role has a specific set of permissions that can be used to build custom roles.
"""

# Permission categories for better organization
PERMISSION_CATEGORIES = {
    'IOC Management': {
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
    },
    'Case Management': {
        'case.view': 'View cases',
        'case.create': 'Create cases',
        'case.edit': 'Edit cases',
        'case.delete': 'Delete cases',
        'case.assign': 'Assign cases to users',
        'case.close': 'Close cases',
        'case.reopen': 'Reopen closed cases',
    },
    'Incident Management': {
        'incident.view': 'View incidents',
        'incident.create': 'Create incidents',
        'incident.edit': 'Edit incidents',
        'incident.delete': 'Delete incidents',
        'incident.report': 'Generate incident reports',
        'incident.escalate': 'Escalate incidents',
    },
    'Comments & Collaboration': {
        'comment.view': 'View comments',
        'comment.create': 'Create comments',
        'comment.edit': 'Edit own comments',
        'comment.delete': 'Delete own comments',
        'comment.edit_any': 'Edit any comment',
        'comment.delete_any': 'Delete any comment',
    },
    'Snippets & Templates': {
        'snippet.view': 'View snippets',
        'snippet.create': 'Create snippets',
        'snippet.edit': 'Edit own snippets',
        'snippet.delete': 'Delete own snippets',
        'snippet.edit_any': 'Edit any snippet',
        'snippet.delete_any': 'Delete any snippet',
        'snippet.manage_global': 'Manage global snippets',
    },
    'Timeline Management': {
        'timeline.view': 'View timeline',
        'timeline.create': 'Create timeline events',
        'timeline.edit': 'Edit timeline events',
        'timeline.delete': 'Delete timeline events',
    },
    'API & Integration': {
        'api.access': 'Access API',
        'api.keys.view': 'View API keys',
        'api.keys.create': 'Create API keys',
        'api.keys.delete': 'Delete API keys',
        'api.external.view': 'View external API configurations',
        'api.external.configure': 'Configure external APIs',
        'api.external.test': 'Test external APIs',
    },
    'Webhook Management': {
        'webhook.view': 'View webhooks',
        'webhook.create': 'Create webhooks',
        'webhook.edit': 'Edit webhooks',
        'webhook.delete': 'Delete webhooks',
        'webhook.test': 'Test webhooks',
    },
    'Search & Reports': {
        'search.advanced': 'Access advanced search',
        'report.view': 'View reports',
        'report.create': 'Create reports',
        'report.export': 'Export reports',
    },
    'Public Submissions': {
        'submission.view': 'View public submissions',
        'submission.create': 'Create IOCs from submissions',
        'submission.manage': 'Manage submissions (review, reject)',
    },
    'Audit & Monitoring': {
        'audit.view': 'View audit logs and Elasticsearch stats',
        'audit.export': 'Export audit logs',
    },
    'Administration': {
        'admin.users.view': 'View users',
        'admin.users.create': 'Create users',
        'admin.users.edit': 'Edit users',
        'admin.users.delete': 'Delete users',
        'admin.users.assign_role': 'Assign roles to users',
        'admin.roles.view': 'View roles',
        'admin.roles.create': 'Create custom roles',
        'admin.roles.edit': 'Edit roles',
        'admin.roles.delete': 'Delete custom roles',
        'admin.settings': 'Manage site settings',
        'admin.audit': 'Manage audit system',
        'admin.tasks': 'Manage scheduled tasks',
        'admin.import_jobs': 'Manage import jobs',
    }
}

# Permission Matrix - Maps roles to feature sets
PERMISSION_MATRIX = {
    'Admin': {
        'IOC Management': ['view', 'create', 'edit', 'delete', 'export', 'import', 'enrich', 'relations'],
        'Case Management': ['view', 'create', 'edit', 'delete', 'assign', 'close', 'reopen'],
        'Incident Management': ['view', 'create', 'edit', 'delete', 'report', 'escalate'],
        'Comments & Collaboration': ['view', 'create', 'edit', 'delete', 'delete_any'],
        'Snippets & Templates': ['view', 'create', 'edit', 'delete', 'delete_any', 'manage_global'],
        'Timeline Management': ['view', 'create', 'edit', 'delete'],
        'API & Integration': ['access', 'keys_view', 'keys_create', 'keys_delete', 'external_view', 'external_configure', 'external_test'],
        'Webhook Management': ['view', 'create', 'edit', 'delete', 'test'],
        'Search & Reports': ['advanced', 'view', 'create', 'export'],
        'Public Submissions': ['view', 'create', 'manage'],
        'Audit & Monitoring': ['view', 'export'],
        'Administration': ['users_view', 'users_create', 'users_edit', 'users_delete', 'users_assign_role', 'roles_view', 'roles_create', 'roles_edit', 'roles_delete', 'settings', 'audit', 'tasks', 'import_jobs'],
    },
    'Security Analyst': {
        'IOC Management': ['view', 'create', 'edit', 'export', 'import', 'enrich', 'relations'],
        'Case Management': ['view', 'create', 'edit', 'assign', 'close'],
        'Incident Management': ['view', 'create', 'edit', 'report', 'escalate'],
        'Comments & Collaboration': ['view', 'create', 'edit', 'delete_any'],
        'Snippets & Templates': ['view', 'create', 'edit'],
        'Timeline Management': ['view', 'create', 'edit'],
        'API & Integration': ['access', 'keys_view', 'keys_create', 'external_view', 'external_test'],
        'Webhook Management': ['view'],
        'Search & Reports': ['advanced', 'view', 'create', 'export'],
        'Public Submissions': ['view', 'create', 'manage'],
        'Audit & Monitoring': ['view'],
    },
    'Threat Intel Officer': {
        'IOC Management': ['view', 'create', 'edit', 'export', 'import', 'enrich', 'relations'],
        'Case Management': ['view'],
        'Incident Management': ['view'],
        'Comments & Collaboration': ['view', 'create', 'edit'],
        'Snippets & Templates': ['view', 'create', 'edit', 'manage_global'],
        'Timeline Management': ['view', 'create'],
        'API & Integration': ['access', 'keys_view', 'external_view', 'external_test'],
        'Search & Reports': ['advanced', 'view', 'create', 'export'],
        'Public Submissions': ['view', 'create', 'manage'],
        'Audit & Monitoring': ['view'],
    },
    'Incident Responder': {
        'IOC Management': ['view', 'create', 'edit', 'relations'],
        'Case Management': ['view', 'create', 'edit', 'assign', 'close', 'reopen'],
        'Incident Management': ['view', 'create', 'edit', 'escalate', 'report'],
        'Comments & Collaboration': ['view', 'create', 'edit', 'delete_any'],
        'Snippets & Templates': ['view', 'create', 'edit'],
        'Timeline Management': ['view', 'create', 'edit'],
        'API & Integration': ['access', 'keys_view'],
        'Webhook Management': ['view'],
        'Search & Reports': ['advanced', 'view', 'create', 'export'],
        'Public Submissions': ['view', 'create'],
        'Audit & Monitoring': ['view'],
    },
    'Manager': {
        'IOC Management': ['view', 'export', 'relations'],
        'Case Management': ['view', 'create', 'edit', 'assign', 'close'],
        'Incident Management': ['view', 'create', 'edit', 'report'],
        'Comments & Collaboration': ['view', 'create', 'edit'],
        'Snippets & Templates': ['view', 'create'],
        'Timeline Management': ['view'],
        'API & Integration': ['access', 'keys_view'],
        'Search & Reports': ['advanced', 'view', 'create', 'export'],
        'Public Submissions': ['view', 'manage'],
        'Audit & Monitoring': ['view'],
        'Administration': ['users_view', 'roles_view', 'audit'],
    },
    'Viewer': {
        'IOC Management': ['view', 'export', 'relations'],
        'Case Management': ['view'],
        'Incident Management': ['view'],
        'Comments & Collaboration': ['view', 'create'],
        'Snippets & Templates': ['view'],
        'Timeline Management': ['view'],
        'API & Integration': ['access', 'keys_view'],
        'Search & Reports': ['advanced', 'view', 'export'],
        'Public Submissions': ['view'],
    }
}


def get_permission_matrix():
    """Get the complete permission matrix."""
    return PERMISSION_MATRIX


def get_categories():
    """Get all permission categories."""
    return PERMISSION_CATEGORIES


def get_role_permissions(role_name: str) -> dict:
    """Get permissions for a specific role."""
    return PERMISSION_MATRIX.get(role_name, {})


def get_feature_permissions(category: str) -> dict:
    """Get all permissions for a specific feature category."""
    return PERMISSION_CATEGORIES.get(category, {})
