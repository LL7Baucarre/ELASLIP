"""Service for managing public submissions."""

from datetime import datetime
from typing import Dict, List, Optional
import uuid

from app.services.base_service import BaseListService
from app.utils.pattern_generator import PatternGenerator


class SubmissionService(BaseListService):
    """Service for managing external user submissions."""
    
    def __init__(self):
        super().__init__()
        self.index = 'elaslip_submissions'
    
    def create_submission(self,
                         ioc_type: str,
                         ioc_value: str,
                         submitter_email: str = None,
                         submitter_name: str = None,
                         submitter_organization: str = None,
                         description: str = None,
                         reason: str = None,
                         tags: List[str] = None,
                         confidence: str = 'medium') -> Dict:
        """
        Create a new external submission.
        
        Args:
            ioc_type: Type of IOC (md5, sha256, ipv4, domain, email, url, etc.)
            ioc_value: The IOC value
            submitter_email: Email of the submitter
            submitter_name: Name of the submitter
            submitter_organization: Organization of the submitter
            description: Description of the IOC
            reason: Reason for submission
            tags: Tags/labels for the submission
            confidence: Confidence level (high, medium, low)
        
        Returns:
            Created submission document
        
        Raises:
            ValueError: If IOC type is invalid or value is invalid
        """
        # Validate IOC type and value
        if ioc_type not in PatternGenerator.get_supported_types():
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        
        if not PatternGenerator.validate_value(ioc_type, ioc_value):
            raise ValueError(f"Invalid {ioc_type} value: {ioc_value}")
        
        submission_id = f"submission--{uuid.uuid4()}"
        now = datetime.utcnow().isoformat() + 'Z'
        
        # Check if this IOC has been previously rejected
        rejected_submissions = self._find_rejected_submissions_for_value(ioc_type, ioc_value)
        if rejected_submissions:
            raise ValueError(f"This IOC ({ioc_type}: {ioc_value}) has already been reviewed and rejected. Please contact an administrator if you believe this is an error.")
        
        # Check if this is a duplicate submission
        existing_submissions = self._find_duplicate_submissions_for_value(ioc_type, ioc_value)
        is_duplicate = len(existing_submissions) > 0
        duplicate_of = existing_submissions[0] if is_duplicate else None
        
        submission = {
            'id': submission_id,
            'submission_type': 'external_submission',
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'submitter_email': submitter_email,
            'submitter_name': submitter_name,
            'submitter_organization': submitter_organization,
            'description': description,
            'reason': reason,
            'tags': tags or [],
            'status': 'duplicate' if is_duplicate else 'pending',
            'duplicate_of': duplicate_of,
            'matched_iocs': [],
            'created_ioc_id': None,
            'analyst_notes': None,
            'analyst_user_id': None,
            'analyst_username': None,
            'reviewed_at': None,
            'created_at': now,
            'updated_at': now,
            'response_actions': None,
            'confidence': confidence
        }
        
        # Index the submission
        self.es.index(index=self.index, doc_id=submission_id, document=submission)
        submission['id'] = submission_id
        return submission
    
    def _find_duplicate_submissions_for_value(self, ioc_type: str, ioc_value: str) -> List[str]:
        """Find existing pending submissions for the same IOC type and value."""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'ioc_type': ioc_type}},
                            {'term': {'ioc_value.keyword': ioc_value}},
                            {'term': {'status': 'pending'}}
                        ]
                    }
                },
                'size': 1,
                'sort': [{'created_at': {'order': 'asc'}}]
            }
            result = self.es.search(self.index, query)
            return [hit['_id'] for hit in result.get('hits', {}).get('hits', [])]
        except Exception:
            return []
    
    def _find_rejected_submissions_for_value(self, ioc_type: str, ioc_value: str) -> List[str]:
        """Find existing rejected submissions for the same IOC type and value."""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'ioc_type': ioc_type}},
                            {'term': {'ioc_value.keyword': ioc_value}},
                            {'term': {'status': 'rejected'}}
                        ]
                    }
                },
                'size': 1,
                'sort': [{'created_at': {'order': 'desc'}}]
            }
            result = self.es.search(self.index, query)
            return [hit['_id'] for hit in result.get('hits', {}).get('hits', [])]
        except Exception:
            return []
    
    def get_submission(self, submission_id: str) -> Optional[Dict]:
        """Get a specific submission."""
        try:
            result = self.es.get(index=self.index, doc_id=submission_id)
            submission = result['_source']
            submission['id'] = result['_id']
            return submission
        except Exception:
            return None
    
    def list_submissions(self,
                        page: int = 1,
                        per_page: int = 20,
                        status: str = None,
                        sort_field: str = 'created_at',
                        sort_order: str = 'desc') -> Dict:
        """
        List submissions with pagination.
        
        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            status: Filter by status (pending, processed, created_ioc, rejected)
            sort_field: Field to sort by
            sort_order: Sort order (asc, desc)
        
        Returns:
            Paginated response
        """
        query = {
            'from': (page - 1) * per_page,
            'size': per_page,
            'sort': self.build_sort_config(sort_field, sort_order)
        }
        
        # Add status filter if provided
        if status:
            query['query'] = {
                'term': {'status': status}
            }
        else:
            query['query'] = {'match_all': {}}
        
        result = self.es.search(self.index, query)
        items = self.build_hits_from_search(result)
        
        return self.build_paginated_response(result, page, per_page, items)
    
    def update_submission(self,
                         submission_id: str,
                         analyst_notes: str = None,
                         analyst_user_id: str = None,
                         analyst_username: str = None,
                         status: str = None,
                         response_actions: str = None,
                         created_ioc_id: str = None) -> Dict:
        """Update submission with analyst review."""
        submission = self.get_submission(submission_id)
        if not submission:
            raise ValueError(f"Submission {submission_id} not found")
        
        update = {
            'doc': {
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            }
        }
        
        if analyst_notes is not None:
            update['doc']['analyst_notes'] = analyst_notes
        if analyst_user_id is not None:
            update['doc']['analyst_user_id'] = analyst_user_id
        if analyst_username is not None:
            update['doc']['analyst_username'] = analyst_username
        if status is not None:
            update['doc']['status'] = status
        if response_actions is not None:
            update['doc']['response_actions'] = response_actions
        if created_ioc_id is not None:
            update['doc']['created_ioc_id'] = created_ioc_id
            update['doc']['status'] = 'created_ioc'
        
        if status and not created_ioc_id:
            update['doc']['reviewed_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.es.update(index=self.index, doc_id=submission_id, body=update)
        return self.get_submission(submission_id)
    
    def public_search(self,
                     ioc_type: str,
                     ioc_value: str,
                     max_results: int = 10) -> Dict:
        """
        Public search - returns matching IOCs if they exist (TLP white/green only).
        This is for the public submissions page.
        
        Args:
            ioc_type: Type of IOC to search
            ioc_value: Value of IOC to search
            max_results: Maximum results to return
        
        Returns:
            Search results with matched IOCs and threat information
        """
        # Validate input
        if ioc_type not in PatternGenerator.SUPPORTED_TYPES:
            return {
                'found': False,
                'error': f'Unsupported IOC type: {ioc_type}',
                'results': []
            }
        
        if not PatternGenerator.validate_value(ioc_type, ioc_value):
            return {
                'found': False,
                'error': f'Invalid {ioc_type} value format',
                'results': []
            }
        
        try:
            # Search for matching IOCs - TLP white/green OR no TLP (defaults to public)
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'x_metadata.ioc_type': ioc_type}},
                            {'term': {'x_metadata.ioc_value': ioc_value}},
                        ],
                        'should': [
                            {'term': {'x_metadata.tlp': 'white'}},
                            {'term': {'x_metadata.tlp': 'green'}},
                            {'bool': {'must_not': {'exists': {'field': 'x_metadata.tlp'}}}}
                        ],
                        'minimum_should_match': 1
                    }
                },
                'size': max_results
            }
            
            result = self.es.search('ioc', query)
            hits = result.get('hits', {}).get('hits', [])
            
            if hits:
                results = []
                for hit in hits:
                    source = hit['_source']
                    results.append({
                        'id': hit['_id'],
                        'threat_level': source.get('x_metadata', {}).get('threat_level', 'unknown'),
                        'tlp': source.get('x_metadata', {}).get('tlp', 'unknown'),
                        'confidence': source.get('x_metadata', {}).get('confidence', 'unknown'),
                        'risk_score': source.get('x_metadata', {}).get('risk_score', 0),
                        'status': source.get('x_metadata', {}).get('status', 'unknown'),
                        'campaigns': source.get('x_metadata', {}).get('campaigns', []),
                        'description': source.get('description'),
                        'name': source.get('name'),
                        'response_actions': source.get('x_metadata', {}).get('response_actions'),
                    })
                
                return {
                    'found': True,
                    'count': len(results),
                    'results': results
                }
            else:
                return {
                    'found': False,
                    'count': 0,
                    'results': []
                }
        
        except Exception as e:
            return {
                'found': False,
                'error': f'Search error: {str(e)}',
                'results': []
            }
    
    def get_submissions_by_status(self, status: str, page: int = 1, per_page: int = 20) -> Dict:
        """Get submissions filtered by status."""
        return self.list_submissions(page=page, per_page=per_page, status=status)
    
    def reject_submission(self,
                         submission_id: str,
                         rejection_reason: str = None,
                         analyst_user_id: str = None,
                         analyst_username: str = None) -> Dict:
        """Reject a submission."""
        return self.update_submission(
            submission_id=submission_id,
            status='rejected',
            analyst_notes=rejection_reason,
            analyst_user_id=analyst_user_id,
            analyst_username=analyst_username
        )
    
    def find_duplicate_submissions(self, submission_id: str) -> List[Dict]:
        """
        Find duplicate submissions for the same IOC.
        Duplicates are defined as submissions with the same ioc_type + ioc_value.
        
        Args:
            submission_id: The submission ID to find duplicates for
        
        Returns:
            List of duplicate submissions (excluding the current one)
        """
        submission = self.get_submission(submission_id)
        if not submission:
            return []
        
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'ioc_type': submission['ioc_type']}},
                            {'term': {'ioc_value.keyword': submission['ioc_value']}}
                        ],
                        'must_not': [
                            {'term': {'_id': submission_id}}
                        ]
                    }
                },
                'size': 100,
                'sort': [{'created_at': {'order': 'desc'}}]
            }
            result = self.es.search(self.index, query)
            duplicates = self.build_hits_from_search(result)
            return duplicates
        except Exception:
            return []
    
    def mark_duplicate(self, submission_id: str, original_submission_id: str) -> Dict:
        """
        Mark a submission as a duplicate of another.
        
        Args:
            submission_id: The duplicate submission ID
            original_submission_id: The original submission ID
        
        Returns:
            Updated submission
        """
        submission = self.get_submission(submission_id)
        if not submission:
            raise ValueError(f"Submission {submission_id} not found")
        
        original = self.get_submission(original_submission_id)
        if not original:
            raise ValueError(f"Original submission {original_submission_id} not found")
        
        update = {
            'doc': {
                'status': 'duplicate',
                'duplicate_of': original_submission_id,
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            }
        }
        
        self.es.update(index=self.index, doc_id=submission_id, body=update)
        return self.get_submission(submission_id)
    
    def merge_duplicate_submissions(self, submission_ids: List[str], primary_submission_id: str = None) -> Dict:
        """
        Merge multiple duplicate submissions into one.
        
        Args:
            submission_ids: List of submission IDs to merge
            primary_submission_id: The ID of the submission to keep (if None, uses the first one)
        
        Returns:
            The primary submission with merged data
        """
        if not submission_ids:
            raise ValueError("At least one submission ID required")
        
        if primary_submission_id is None:
            primary_submission_id = submission_ids[0]
        
        primary = self.get_submission(primary_submission_id)
        if not primary:
            raise ValueError(f"Primary submission {primary_submission_id} not found")
        
        # Collect tags and submitter info from all duplicates
        all_tags = set(primary.get('tags', []))
        submitter_emails = [primary.get('submitter_email')] if primary.get('submitter_email') else []
        
        # Mark all other submissions as duplicates
        for sub_id in submission_ids:
            if sub_id != primary_submission_id:
                submission = self.get_submission(sub_id)
                if submission:
                    # Add tags
                    all_tags.update(submission.get('tags', []))
                    # Collect emails
                    if submission.get('submitter_email'):
                        submitter_emails.append(submission['submitter_email'])
                    
                    # Mark as duplicate
                    self.mark_duplicate(sub_id, primary_submission_id)
        
        # Update primary with merged data
        update = {
            'doc': {
                'tags': list(all_tags),
                'submitter_emails': list(set(submitter_emails)),
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            }
        }
        
        self.es.update(index=self.index, doc_id=primary_submission_id, body=update)
        return self.get_submission(primary_submission_id)
