"""Case and Incident Management Service."""

from datetime import datetime
from typing import Dict, List, Optional
import secrets

from app.services.elasticsearch_service import ElasticsearchService
from app.services.audit_service import AuditService


class CaseService:
    """Service for managing security cases."""
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.audit = AuditService()
    
    # ========================================
    # CASE MANAGEMENT
    # ========================================
    
    def create_case(self, data: Dict, user_id: str, username: str) -> Dict:
        """Create a new case."""
        case_id = secrets.token_hex(16)
        
        case_doc = {
            'id': case_id,
            'title': data.get('title', '').strip(),
            'description': data.get('description', ''),
            'status': data.get('status', 'open'),
            'priority': data.get('priority', 'medium'),
            'severity': data.get('severity', 'medium'),
            'case_type': data.get('case_type', 'investigation'),
            'assignee_id': data.get('assignee_id'),
            'assignee_name': data.get('assignee_name'),
            'created_by_id': user_id,
            'created_by_name': username,
            'tags': data.get('tags', []),
            'tlp': data.get('tlp', 'amber'),
            'ioc_ids': data.get('ioc_ids', []),
            'incident_ids': [],
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'closed_at': None,
            'due_date': data.get('due_date')
        }
        
        self.es.index('cases', case_id, case_doc)
        
        # Audit log
        self.audit.log(
            action='create',
            entity_type='case',
            entity_id=case_id,
            entity_name=case_doc['title'],
            user_id=user_id,
            username=username
        )
        
        return case_doc
    
    def get_case(self, case_id: str) -> Optional[Dict]:
        """Get a case by ID."""
        try:
            result = self.es.get('cases', case_id)
            if result:
                case = result['_source']
                case['id'] = result['_id']
                return case
        except Exception:
            pass
        return None
    
    def update_case(self, case_id: str, updates: Dict, user_id: str, username: str) -> Optional[Dict]:
        """Update a case."""
        case = self.get_case(case_id)
        if not case:
            return None
        
        allowed_fields = [
            'title', 'description', 'status', 'priority', 'severity', 'case_type',
            'assignee_id', 'assignee_name', 'tags', 'tlp', 'ioc_ids', 'due_date'
        ]
        
        update_doc = {k: v for k, v in updates.items() if k in allowed_fields}
        update_doc['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        # Handle status changes
        if updates.get('status') == 'closed' and case['status'] != 'closed':
            update_doc['closed_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.es.update('cases', case_id, {'doc': update_doc})
        
        # Audit log
        self.audit.log(
            action='update',
            entity_type='case',
            entity_id=case_id,
            entity_name=case['title'],
            changes=updates,
            user_id=user_id,
            username=username
        )
        
        return self.get_case(case_id)
    
    def delete_case(self, case_id: str, user_id: str, username: str) -> bool:
        """Delete a case."""
        case = self.get_case(case_id)
        if not case:
            return False
        
        self.es.delete('cases', case_id)
        
        # Audit log
        self.audit.log(
            action='delete',
            entity_type='case',
            entity_id=case_id,
            entity_name=case['title'],
            user_id=user_id,
            username=username
        )
        
        return True
    
    def list_cases(self, page: int = 1, per_page: int = 20, filters: Dict = None) -> Dict:
        """List cases with pagination and filters."""
        from_idx = (page - 1) * per_page
        
        query = {'bool': {'must': []}}
        
        if filters:
            if filters.get('status'):
                query['bool']['must'].append({'term': {'status': filters['status']}})
            if filters.get('priority'):
                query['bool']['must'].append({'term': {'priority': filters['priority']}})
            if filters.get('case_type'):
                query['bool']['must'].append({'term': {'case_type': filters['case_type']}})
            if filters.get('assignee_id'):
                query['bool']['must'].append({'term': {'assignee_id': filters['assignee_id']}})
            if filters.get('search'):
                query['bool']['must'].append({
                    'multi_match': {
                        'query': filters['search'],
                        'fields': ['title', 'description']
                    }
                })
        
        if not query['bool']['must']:
            query = {'match_all': {}}
        
        result = self.es.search('cases', {
            'query': query,
            'sort': [{'updated_at': {'order': 'desc'}}],
            'from': from_idx,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            case = hit['_source']
            case['id'] = hit['_id']
            items.append(case)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def add_iocs_to_case(self, case_id: str, ioc_ids: List[str], user_id: str, username: str) -> Optional[Dict]:
        """Add IOCs to a case."""
        case = self.get_case(case_id)
        if not case:
            return None
        
        current_iocs = set(case.get('ioc_ids', []))
        current_iocs.update(ioc_ids)
        
        return self.update_case(case_id, {'ioc_ids': list(current_iocs)}, user_id, username)
    
    def remove_ioc_from_case(self, case_id: str, ioc_id: str, user_id: str, username: str) -> Optional[Dict]:
        """Remove an IOC from a case."""
        case = self.get_case(case_id)
        if not case:
            return None
        
        ioc_ids = [i for i in case.get('ioc_ids', []) if i != ioc_id]
        return self.update_case(case_id, {'ioc_ids': ioc_ids}, user_id, username)
    
    def link_incident(self, case_id: str, incident_id: str) -> Optional[Dict]:
        """Link an incident to a case."""
        case = self.get_case(case_id)
        if not case:
            return None
        
        incident_ids = case.get('incident_ids', [])
        if incident_id not in incident_ids:
            incident_ids.append(incident_id)
            self.es.update('cases', case_id, {'doc': {'incident_ids': incident_ids}})
        
        return self.get_case(case_id)
    
    def get_case_stats(self) -> Dict:
        """Get case statistics."""
        result = self.es.search('cases', {
            'size': 0,
            'aggs': {
                'by_status': {'terms': {'field': 'status'}},
                'by_priority': {'terms': {'field': 'priority'}},
                'by_type': {'terms': {'field': 'case_type'}}
            }
        })
        
        return {
            'by_status': {b['key']: b['doc_count'] for b in result['aggregations']['by_status']['buckets']},
            'by_priority': {b['key']: b['doc_count'] for b in result['aggregations']['by_priority']['buckets']},
            'by_type': {b['key']: b['doc_count'] for b in result['aggregations']['by_type']['buckets']}
        }


class IncidentService:
    """Service for managing security incidents."""
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.audit = AuditService()
        self.case_service = CaseService()
    
    def create_incident(self, data: Dict, user_id: str, username: str) -> Dict:
        """Create a new incident."""
        incident_id = secrets.token_hex(16)
        
        incident_doc = {
            'id': incident_id,
            'case_id': data.get('case_id'),
            'title': data.get('title', '').strip(),
            'description': data.get('description', ''),
            'status': data.get('status', 'detected'),
            'severity': data.get('severity', 'medium'),
            'category': data.get('category', 'other'),
            'ioc_ids': data.get('ioc_ids', []),
            'affected_assets': data.get('affected_assets', ''),
            'attack_vector': data.get('attack_vector'),
            'mitre_tactics': data.get('mitre_tactics', []),
            'mitre_techniques': data.get('mitre_techniques', []),
            'report_content': data.get('report_content', ''),
            'report_sections': data.get('report_sections', {}),
            'created_by_id': user_id,
            'created_by_name': username,
            'assignee_id': data.get('assignee_id'),
            'assignee_name': data.get('assignee_name'),
            'detected_at': data.get('detected_at', datetime.utcnow().isoformat() + 'Z'),
            'contained_at': None,
            'resolved_at': None,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('incidents', incident_id, incident_doc)
        
        # Link incident to case if case_id provided
        if data.get('case_id'):
            case = self.case_service.get_case(data['case_id'])
            if case:
                incident_ids = case.get('incident_ids', [])
                incident_ids.append(incident_id)
                self.es.update('cases', data['case_id'], {'doc': {'incident_ids': incident_ids}})
        
        # Audit log
        self.audit.log(
            action='create',
            entity_type='incident',
            entity_id=incident_id,
            entity_name=incident_doc['title'],
            user_id=user_id,
            username=username
        )
        
        return incident_doc
    
    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get an incident by ID."""
        try:
            result = self.es.get('incidents', incident_id)
            if result:
                incident = result['_source']
                incident['id'] = result['_id']
                return incident
        except Exception:
            pass
        return None
    
    def update_incident(self, incident_id: str, updates: Dict, user_id: str, username: str) -> Optional[Dict]:
        """Update an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        
        allowed_fields = [
            'title', 'description', 'status', 'severity', 'category', 'ioc_ids',
            'affected_assets', 'attack_vector', 'mitre_tactics', 'mitre_techniques',
            'report_content', 'report_sections', 'assignee_id', 'assignee_name'
        ]
        
        update_doc = {k: v for k, v in updates.items() if k in allowed_fields}
        update_doc['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        # Handle status changes
        if updates.get('status') == 'contained' and incident['status'] != 'contained':
            update_doc['contained_at'] = datetime.utcnow().isoformat() + 'Z'
        if updates.get('status') in ['recovered', 'closed'] and incident['status'] not in ['recovered', 'closed']:
            update_doc['resolved_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.es.update('incidents', incident_id, {'doc': update_doc})
        
        # Audit log
        self.audit.log(
            action='update',
            entity_type='incident',
            entity_id=incident_id,
            entity_name=incident['title'],
            changes=updates,
            user_id=user_id,
            username=username
        )
        
        return self.get_incident(incident_id)
    
    def update_status(self, incident_id: str, status: str, user_id: str, username: str) -> Optional[Dict]:
        """Update incident status."""
        return self.update_incident(incident_id, {'status': status}, user_id, username)
    
    def delete_incident(self, incident_id: str, user_id: str, username: str) -> bool:
        """Delete an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return False
        
        self.es.delete('incidents', incident_id)
        
        # Audit log
        self.audit.log(
            action='delete',
            entity_type='incident',
            entity_id=incident_id,
            entity_name=incident['title'],
            user_id=user_id,
            username=username
        )
        
        return True
    
    def list_incidents(self, page: int = 1, per_page: int = 20, filters: Dict = None) -> Dict:
        """List incidents with pagination and filters."""
        from_idx = (page - 1) * per_page
        
        query = {'bool': {'must': []}}
        
        if filters:
            if filters.get('case_id'):
                query['bool']['must'].append({'term': {'case_id': filters['case_id']}})
            if filters.get('status'):
                query['bool']['must'].append({'term': {'status': filters['status']}})
            if filters.get('severity'):
                query['bool']['must'].append({'term': {'severity': filters['severity']}})
            if filters.get('category'):
                query['bool']['must'].append({'term': {'category': filters['category']}})
            if filters.get('search'):
                query['bool']['must'].append({
                    'multi_match': {
                        'query': filters['search'],
                        'fields': ['title', 'description', 'report_content']
                    }
                })
        
        if not query['bool']['must']:
            query = {'match_all': {}}
        
        result = self.es.search('incidents', {
            'query': query,
            'sort': [{'updated_at': {'order': 'desc'}}],
            'from': from_idx,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            incident = hit['_source']
            incident['id'] = hit['_id']
            items.append(incident)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def add_iocs_to_incident(self, incident_id: str, ioc_ids: List[str], user_id: str, username: str) -> Optional[Dict]:
        """Add IOCs to an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        
        current_iocs = set(incident.get('ioc_ids', []))
        current_iocs.update(ioc_ids)
        
        return self.update_incident(incident_id, {'ioc_ids': list(current_iocs)}, user_id, username)
    
    def update_report(self, incident_id: str, report_content: str, report_sections: Dict,
                      user_id: str, username: str) -> Optional[Dict]:
        """Update incident report."""
        return self.update_incident(incident_id, {
            'report_content': report_content,
            'report_sections': report_sections
        }, user_id, username)
    
    def update_report_section(self, incident_id: str, section: str, content: str) -> bool:
        """Update a single report section."""
        incident = self.get_incident(incident_id)
        if not incident:
            return False
        
        report_sections = incident.get('report_sections', {})
        report_sections[section] = content
        
        self.es.update('incidents', incident_id, {
            'doc': {
                'report_sections': report_sections,
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            }
        })
        
        return True


class TimelineService:
    """Service for managing investigation timeline events."""
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def add_event(self, data: Dict, user_id: str, username: str) -> Dict:
        """Add a timeline event."""
        event_id = secrets.token_hex(16)
        
        event_doc = {
            'id': event_id,
            'case_id': data.get('case_id'),
            'incident_id': data.get('incident_id'),
            'event_type': data.get('event_type', 'note'),
            'title': data.get('title', ''),
            'description': data.get('description', ''),
            'content': data.get('content', ''),
            'attachments': data.get('attachments', []),
            'ioc_ids': data.get('ioc_ids', []),
            'created_by_id': user_id,
            'created_by_name': username,
            'event_time': data.get('event_time', datetime.utcnow().isoformat() + 'Z'),
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('timeline_events', event_id, event_doc)
        return event_doc
    
    def get_event(self, event_id: str) -> Optional[Dict]:
        """Get a timeline event."""
        try:
            result = self.es.get('timeline_events', event_id)
            if result:
                event = result['_source']
                event['id'] = result['_id']
                return event
        except Exception:
            pass
        return None
    
    def update_event(self, event_id: str, updates: Dict) -> Optional[Dict]:
        """Update a timeline event."""
        event = self.get_event(event_id)
        if not event:
            return None
        
        allowed_fields = ['title', 'description', 'content', 'event_type', 'event_time', 'ioc_ids']
        update_doc = {k: v for k, v in updates.items() if k in allowed_fields}
        
        self.es.update('timeline_events', event_id, {'doc': update_doc})
        return self.get_event(event_id)
    
    def delete_event(self, event_id: str) -> bool:
        """Delete a timeline event."""
        try:
            self.es.delete('timeline_events', event_id)
            return True
        except Exception:
            return False
    
    def get_timeline(self, case_id: str = None, incident_id: str = None, 
                     page: int = 1, per_page: int = 50) -> Dict:
        """Get timeline events for a case or incident."""
        from_idx = (page - 1) * per_page
        
        query = {'bool': {'should': [], 'minimum_should_match': 1}}
        
        if case_id:
            query['bool']['should'].append({'term': {'case_id': case_id}})
        if incident_id:
            query['bool']['should'].append({'term': {'incident_id': incident_id}})
        
        if not query['bool']['should']:
            query = {'match_all': {}}
        
        result = self.es.search('timeline_events', {
            'query': query,
            'sort': [{'event_time': {'order': 'desc'}}],
            'from': from_idx,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            event = hit['_source']
            event['id'] = hit['_id']
            items.append(event)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
