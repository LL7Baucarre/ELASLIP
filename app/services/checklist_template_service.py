"""Checklist Template Service for managing reusable checklist templates."""

from datetime import datetime
from typing import Dict, List, Optional
import uuid

from app.services.elasticsearch_service import ElasticsearchService


class ChecklistTemplateService:
    """Service to manage checklist templates."""
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def create_template(self, name: str, description: str = '', created_by: str = '', 
                       items: List[Dict] = None, is_public: bool = False) -> Dict:
        """Create a new checklist template."""
        if items is None:
            items = []
        
        template = {
            'id': str(uuid.uuid4()),
            'name': name,
            'description': description,
            'items': items,  # List of {id, title, description}
            'created_by': created_by,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'is_public': is_public,
        }
        
        self.es.index('checklist_templates', template['id'], template)
        return template
    
    def get_template(self, template_id: str) -> Optional[Dict]:
        """Get a template by ID."""
        try:
            result = self.es.get('checklist_templates', template_id)
            if result and 'found' in result and result['found']:
                doc = result['_source']
                doc['id'] = template_id
                return doc
            return None
        except Exception:
            return None
    
    def list_templates(self, page: int = 1, per_page: int = 20, created_by: str = None, 
                      include_public: bool = True) -> Dict:
        """List templates with pagination."""
        query_conditions = []
        
        if created_by:
            query_conditions.append({'term': {'created_by': created_by}})
        
        if include_public:
            # If filtering by created_by, also include public templates
            if created_by:
                query = {
                    'bool': {
                        'should': [
                            {'term': {'created_by': created_by}},
                            {'term': {'is_public': True}}
                        ]
                    }
                }
            else:
                query = {'match_all': {}}
        else:
            if query_conditions:
                query = {'bool': {'must': query_conditions}}
            else:
                query = {'match_all': {}}
        
        result = self.es.search('checklist_templates', {
            'query': query,
            'sort': [{'created_at': {'order': 'desc'}}],
            'from': (page - 1) * per_page,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            item = hit['_source']
            item['id'] = hit['_id']
            items.append(item)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page,
            'pages': (result['hits']['total']['value'] + per_page - 1) // per_page
        }
    
    def update_template(self, template_id: str, updates: Dict) -> Optional[Dict]:
        """Update a template."""
        try:
            template = self.get_template(template_id)
            if not template:
                return None
            
            # Update allowed fields
            if 'name' in updates:
                template['name'] = updates['name']
            if 'description' in updates:
                template['description'] = updates['description']
            if 'items' in updates:
                template['items'] = updates['items']
            if 'is_public' in updates:
                template['is_public'] = updates['is_public']
            
            template['updated_at'] = datetime.utcnow().isoformat() + 'Z'
            
            # Remove the 'id' field before indexing (it's stored as _id)
            doc = {k: v for k, v in template.items() if k != 'id'}
            self.es.index('checklist_templates', template_id, doc)
            return template
        except Exception:
            return None
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a template."""
        try:
            self.es.delete('checklist_templates', template_id)
            return True
        except Exception:
            return False
    
    def add_item(self, template_id: str, title: str, description: str = '') -> Optional[Dict]:
        """Add an item to a template."""
        try:
            template = self.get_template(template_id)
            if not template:
                return None
            
            item = {
                'id': str(uuid.uuid4()),
                'title': title,
                'description': description
            }
            
            template['items'].append(item)
            template['updated_at'] = datetime.utcnow().isoformat() + 'Z'
            
            doc = {k: v for k, v in template.items() if k != 'id'}
            self.es.index('checklist_templates', template_id, doc)
            return template
        except Exception:
            return None
    
    def update_item(self, template_id: str, item_id: str, title: str = None, 
                   description: str = None) -> Optional[Dict]:
        """Update an item in a template."""
        try:
            template = self.get_template(template_id)
            if not template:
                return None
            
            for item in template.get('items', []):
                if item['id'] == item_id:
                    if title:
                        item['title'] = title
                    if description is not None:
                        item['description'] = description
                    break
            
            template['updated_at'] = datetime.utcnow().isoformat() + 'Z'
            doc = {k: v for k, v in template.items() if k != 'id'}
            self.es.index('checklist_templates', template_id, doc)
            return template
        except Exception:
            return None
    
    def delete_item(self, template_id: str, item_id: str) -> Optional[Dict]:
        """Delete an item from a template."""
        try:
            template = self.get_template(template_id)
            if not template:
                return None
            
            template['items'] = [item for item in template.get('items', []) 
                               if item['id'] != item_id]
            
            template['updated_at'] = datetime.utcnow().isoformat() + 'Z'
            doc = {k: v for k, v in template.items() if k != 'id'}
            self.es.index('checklist_templates', template_id, doc)
            return template
        except Exception:
            return None
    
    def use_template(self, template_id: str) -> Optional[Dict]:
        """Get template data for creating a new checklist from it."""
        try:
            template = self.get_template(template_id)
            if not template:
                return None
            
            return {
                'name': template.get('name'),
                'description': template.get('description'),
                'items': [{'title': item['title'], 'description': item.get('description', '')} 
                         for item in template.get('items', [])]
            }
        except Exception:
            return None
