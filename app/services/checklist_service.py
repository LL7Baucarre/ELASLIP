"""Checklist Service for managing checklists and tasks."""

from datetime import datetime
from typing import Dict, List, Optional
import uuid

from app.services.elasticsearch_service import ElasticsearchService


class ChecklistService:
    """Service to manage checklists."""
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def create_checklist(self, title: str, description: str = '', created_by: str = '', created_by_id: str = '',
                        items: List[Dict] = None, tags: List[str] = None, 
                        campaigns: List[str] = None, comments: List[Dict] = None,
                        related_cases: List[str] = None, related_incidents: List[str] = None,
                        assigned_to: str = '', assigned_to_name: str = '') -> Dict:
        """Create a new checklist."""
        if items is None:
            items = []
        if tags is None:
            tags = []
        if campaigns is None:
            campaigns = []
        if comments is None:
            comments = []
        if related_cases is None:
            related_cases = []
        if related_incidents is None:
            related_incidents = []
        
        # Ensure each item has an ID and completed flag
        for item in items:
            if 'id' not in item:
                item['id'] = str(uuid.uuid4())
            if 'completed' not in item:
                item['completed'] = False
        
        checklist = {
            'id': str(uuid.uuid4()),
            'title': title,
            'description': description,
            'items': items,  # List of {id, title, completed, description, comments}
            'tags': tags,
            'campaigns': campaigns,
            'related_cases': related_cases,
            'related_incidents': related_incidents,
            'comments': comments,
            'created_by': created_by,
            'created_by_id': created_by_id,
            'assigned_to': assigned_to,
            'assigned_to_name': assigned_to_name,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'status': 'in-progress',  # in-progress, completed, archived
        }
        
        self.es.index('checklists', checklist['id'], checklist)
        return checklist
    
    def get_checklist(self, checklist_id: str) -> Optional[Dict]:
        """Get a checklist by ID."""
        try:
            result = self.es.get('checklists', checklist_id)
            if result and 'found' in result and result['found']:
                doc = result['_source']
                doc['id'] = checklist_id
                return doc
            return None
        except Exception:
            return None
    
    def list_checklists(self, page: int = 1, per_page: int = 20, status: str = None) -> Dict:
        """List all checklists with pagination."""
        query = {'match_all': {}}
        
        if status:
            query = {'term': {'status': status}}
        
        result = self.es.search('checklists', {
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
    
    def update_checklist(self, checklist_id: str, updates: Dict) -> Optional[Dict]:
        """Update a checklist."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        # Update allowed fields
        if 'title' in updates:
            checklist['title'] = updates['title']
        if 'description' in updates:
            checklist['description'] = updates['description']
        if 'items' in updates:
            checklist['items'] = updates['items']
        if 'status' in updates:
            checklist['status'] = updates['status']
        
        checklist['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        # Remove the 'id' field before indexing (it's stored as _id)
        doc = {k: v for k, v in checklist.items() if k != 'id'}
        self.es.index('checklists', checklist_id, doc)
        return self.get_checklist(checklist_id)
    
    def delete_checklist(self, checklist_id: str) -> bool:
        """Delete a checklist."""
        try:
            self.es.delete('checklists', checklist_id)
            return True
        except Exception:
            return False
    
    def add_item(self, checklist_id: str, title: str, description: str = '') -> Optional[Dict]:
        """Add an item to a checklist."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        item = {
            'id': str(uuid.uuid4()),
            'title': title,
            'description': description,
            'completed': False,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        checklist['items'].append(item)
        return self.update_checklist(checklist_id, {'items': checklist['items']})
    
    def update_item(self, checklist_id: str, item_id: str, updates: Dict) -> Optional[Dict]:
        """Update an item in a checklist."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        for item in checklist['items']:
            if item['id'] == item_id:
                item.update(updates)
                return self.update_checklist(checklist_id, {'items': checklist['items']})
        
        return None
    
    def toggle_item(self, checklist_id: str, item_id: str) -> Optional[Dict]:
        """Toggle item completion status."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        for item in checklist['items']:
            if item['id'] == item_id:
                item['completed'] = not item.get('completed', False)
                return self.update_checklist(checklist_id, {'items': checklist['items']})
        
        return None
    
    def delete_item(self, checklist_id: str, item_id: str) -> Optional[Dict]:
        """Delete an item from a checklist."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        checklist['items'] = [item for item in checklist['items'] if item['id'] != item_id]
        return self.update_checklist(checklist_id, {'items': checklist['items']})
    
    def add_comment_to_item(self, checklist_id: str, item_id: str, comment_text: str, 
                           user: str = '') -> Optional[Dict]:
        """Add a comment to a checklist item."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        for item in checklist['items']:
            if item['id'] == item_id:
                # Initialize comments list if it doesn't exist
                if 'comments' not in item:
                    item['comments'] = []
                
                # Add new comment
                comment = {
                    'id': str(uuid.uuid4()),
                    'text': comment_text.strip(),
                    'user': user,
                    'created_at': datetime.utcnow().isoformat() + 'Z'
                }
                item['comments'].append(comment)
                return self.update_checklist(checklist_id, {'items': checklist['items']})
        
        return None
    
    def delete_comment_from_item(self, checklist_id: str, item_id: str, comment_id: str) -> Optional[Dict]:
        """Delete a comment from a checklist item."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        for item in checklist['items']:
            if item['id'] == item_id:
                if 'comments' in item:
                    item['comments'] = [c for c in item['comments'] if c['id'] != comment_id]
                    return self.update_checklist(checklist_id, {'items': checklist['items']})
        
        return None
    
    def export_markdown(self, checklist_id: str) -> Optional[str]:
        """Export checklist as Markdown."""
        checklist = self.get_checklist(checklist_id)
        if not checklist:
            return None
        
        md = f"# {checklist['title']}\n\n"
        
        if checklist.get('description'):
            md += f"{checklist['description']}\n\n"
        
        md += f"**Status:** {checklist['status']}\n"
        md += f"**Created by:** {checklist['created_by']}\n"
        md += f"**Created at:** {checklist['created_at']}\n\n"
        
        md += "## Items\n\n"
        
        for item in checklist['items']:
            checkbox = "✓" if item.get('completed') else "☐"
            md += f"- [{checkbox}] {item['title']}"
            if item.get('description'):
                md += f"\n  - {item['description']}"
            md += "\n"
        
        return md
