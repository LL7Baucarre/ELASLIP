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
                        related_cases: List = None, related_incidents: List = None,
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
        
        # Extract IDs from related_cases and related_incidents if they are objects
        related_cases_ids = []
        for case in related_cases:
            if isinstance(case, dict):
                related_cases_ids.append(case.get('id', case))
            else:
                related_cases_ids.append(case)
        
        related_incidents_ids = []
        for incident in related_incidents:
            if isinstance(incident, dict):
                related_incidents_ids.append(incident.get('id', incident))
            else:
                related_incidents_ids.append(incident)
        
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
            'related_cases': related_cases_ids,  # Store IDs in Elasticsearch
            'related_incidents': related_incidents_ids,  # Store IDs in Elasticsearch
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
        
        # Return checklist with original objects for frontend display
        checklist_response = checklist.copy()
        checklist_response['related_cases'] = related_cases
        checklist_response['related_incidents'] = related_incidents
        
        return checklist_response
    
    def get_checklist(self, checklist_id: str) -> Optional[Dict]:
        """Get a checklist by ID."""
        try:
            result = self.es.get('checklists', checklist_id)
            if result and 'found' in result and result['found']:
                doc = result['_source']
                doc['id'] = checklist_id
                
                # Enrich related_cases IDs with titles
                if 'related_cases' in doc and doc['related_cases']:
                    enriched_cases = []
                    for case_id in doc['related_cases']:
                        try:
                            case_result = self.es.get('cases', case_id)
                            if case_result and case_result.get('found'):
                                case_data = case_result['_source']
                                enriched_cases.append({
                                    'id': case_id,
                                    'title': case_data.get('title', case_id)
                                })
                            else:
                                enriched_cases.append({'id': case_id, 'title': case_id})
                        except:
                            enriched_cases.append({'id': case_id, 'title': case_id})
                    doc['related_cases'] = enriched_cases
                
                # Enrich related_incidents IDs with titles
                if 'related_incidents' in doc and doc['related_incidents']:
                    enriched_incidents = []
                    for incident_id in doc['related_incidents']:
                        try:
                            incident_result = self.es.get('incidents', incident_id)
                            if incident_result and incident_result.get('found'):
                                incident_data = incident_result['_source']
                                enriched_incidents.append({
                                    'id': incident_id,
                                    'title': incident_data.get('title', incident_id)
                                })
                            else:
                                enriched_incidents.append({'id': incident_id, 'title': incident_id})
                        except:
                            enriched_incidents.append({'id': incident_id, 'title': incident_id})
                    doc['related_incidents'] = enriched_incidents
                
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
            
            # Enrich related_cases IDs with titles
            if 'related_cases' in item and item['related_cases']:
                enriched_cases = []
                for case_id in item['related_cases']:
                    try:
                        case_result = self.es.get('cases', case_id)
                        if case_result and case_result.get('found'):
                            case_data = case_result['_source']
                            enriched_cases.append({
                                'id': case_id,
                                'title': case_data.get('title', case_id)
                            })
                        else:
                            enriched_cases.append({'id': case_id, 'title': case_id})
                    except:
                        enriched_cases.append({'id': case_id, 'title': case_id})
                item['related_cases'] = enriched_cases
            
            # Enrich related_incidents IDs with titles
            if 'related_incidents' in item and item['related_incidents']:
                enriched_incidents = []
                for incident_id in item['related_incidents']:
                    try:
                        incident_result = self.es.get('incidents', incident_id)
                        if incident_result and incident_result.get('found'):
                            incident_data = incident_result['_source']
                            enriched_incidents.append({
                                'id': incident_id,
                                'title': incident_data.get('title', incident_id)
                            })
                        else:
                            enriched_incidents.append({'id': incident_id, 'title': incident_id})
                    except:
                        enriched_incidents.append({'id': incident_id, 'title': incident_id})
                item['related_incidents'] = enriched_incidents
            
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
        if 'tags' in updates:
            checklist['tags'] = updates['tags']
        if 'campaigns' in updates:
            checklist['campaigns'] = updates['campaigns']
        
        # Handle related_cases - extract IDs if they are objects
        if 'related_cases' in updates:
            related_cases_objects = updates['related_cases']
            related_cases_ids = []
            for case in related_cases_objects:
                if isinstance(case, dict):
                    related_cases_ids.append(case.get('id', case))
                else:
                    related_cases_ids.append(case)
            checklist['related_cases'] = related_cases_ids
            # Store original objects separately for later retrieval
            checklist['_related_cases_objects'] = related_cases_objects
        
        # Handle related_incidents - extract IDs if they are objects
        if 'related_incidents' in updates:
            related_incidents_objects = updates['related_incidents']
            related_incidents_ids = []
            for incident in related_incidents_objects:
                if isinstance(incident, dict):
                    related_incidents_ids.append(incident.get('id', incident))
                else:
                    related_incidents_ids.append(incident)
            checklist['related_incidents'] = related_incidents_ids
            # Store original objects separately for later retrieval
            checklist['_related_incidents_objects'] = related_incidents_objects
        
        if 'assigned_to' in updates:
            checklist['assigned_to'] = updates['assigned_to']
        if 'assigned_to_name' in updates:
            checklist['assigned_to_name'] = updates['assigned_to_name']
        
        checklist['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        # Remove the 'id' field before indexing (it's stored as _id)
        doc = {k: v for k, v in checklist.items() if k != 'id'}
        self.es.index('checklists', checklist_id, doc)
        
        # Return with original objects for frontend display
        checklist_response = self.get_checklist(checklist_id)
        if '_related_cases_objects' in checklist:
            checklist_response['related_cases'] = checklist['_related_cases_objects']
        if '_related_incidents_objects' in checklist:
            checklist_response['related_incidents'] = checklist['_related_incidents_objects']
        
        return checklist_response
    
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
