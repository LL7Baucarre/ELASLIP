"""Comments and Snippets Library Service."""

from datetime import datetime
from typing import Dict, List, Optional
import secrets

from app.services.elasticsearch_service import ElasticsearchService


class CommentService:
    """Service for managing comments on IOCs, incidents, and cases."""
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def create_comment(self, entity_type: str, entity_id: str, content: str,
                       user_id: str, username: str, parent_id: str = None) -> Dict:
        """Create a new comment."""
        comment_id = secrets.token_hex(16)
        
        # Extract mentions from content (format: @username)
        import re
        mentions = re.findall(r'@(\w+)', content)
        
        comment_doc = {
            'id': comment_id,
            'entity_type': entity_type,  # 'ioc', 'incident', 'case'
            'entity_id': entity_id,
            'parent_id': parent_id,  # For threaded replies
            'content': content,
            'mentions': mentions,
            'created_by_id': user_id,
            'created_by_name': username,
            'edited': False,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('comments', comment_id, comment_doc)
        return comment_doc
    
    def get_comment(self, comment_id: str) -> Optional[Dict]:
        """Get a comment by ID."""
        try:
            result = self.es.get('comments', comment_id)
            if result:
                comment = result['_source']
                comment['id'] = result['_id']
                return comment
        except Exception:
            pass
        return None
    
    def update_comment(self, comment_id: str, content: str, user_id: str) -> Optional[Dict]:
        """Update a comment (only by the author)."""
        comment = self.get_comment(comment_id)
        if not comment:
            return None
        
        # Check ownership
        if comment['created_by_id'] != user_id:
            return None
        
        # Extract new mentions
        import re
        mentions = re.findall(r'@(\w+)', content)
        
        update_doc = {
            'content': content,
            'mentions': mentions,
            'edited': True,
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.update('comments', comment_id, {'doc': update_doc})
        return self.get_comment(comment_id)
    
    def delete_comment(self, comment_id: str, user_id: str, is_admin: bool = False) -> bool:
        """Delete a comment (by author or admin)."""
        comment = self.get_comment(comment_id)
        if not comment:
            return False
        
        # Check ownership or admin
        if comment['created_by_id'] != user_id and not is_admin:
            return False
        
        # Delete replies first
        self._delete_replies(comment_id)
        
        self.es.delete('comments', comment_id)
        return True
    
    def _delete_replies(self, parent_id: str):
        """Delete all replies to a comment."""
        result = self.es.search('comments', {
            'query': {'term': {'parent_id': parent_id}},
            'size': 1000
        })
        
        for hit in result['hits']['hits']:
            reply_id = hit['_id']
            self._delete_replies(reply_id)  # Recursive delete
            self.es.delete('comments', reply_id)
    
    def get_comments(self, entity_type: str, entity_id: str, 
                     page: int = 1, per_page: int = 50) -> Dict:
        """Get comments for an entity."""
        from_idx = (page - 1) * per_page
        
        result = self.es.search('comments', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'entity_type': entity_type}},
                        {'term': {'entity_id': entity_id}}
                    ],
                    'must_not': [
                        {'exists': {'field': 'parent_id'}}
                    ]
                }
            },
            'sort': [{'created_at': {'order': 'asc'}}],
            'from': from_idx,
            'size': per_page
        })
        
        comments = []
        for hit in result['hits']['hits']:
            comment = hit['_source']
            comment['id'] = hit['_id']
            # Load replies
            comment['replies'] = self._get_replies(comment['id'])
            comments.append(comment)
        
        return {
            'items': comments,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def _get_replies(self, parent_id: str) -> List[Dict]:
        """Get replies to a comment."""
        result = self.es.search('comments', {
            'query': {'term': {'parent_id': parent_id}},
            'sort': [{'created_at': {'order': 'asc'}}],
            'size': 100
        })
        
        replies = []
        for hit in result['hits']['hits']:
            reply = hit['_source']
            reply['id'] = hit['_id']
            reply['replies'] = self._get_replies(reply['id'])  # Nested replies
            replies.append(reply)
        
        return replies
    
    def get_comment_count(self, entity_type: str, entity_id: str) -> int:
        """Get comment count for an entity."""
        result = self.es.search('comments', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'entity_type': entity_type}},
                        {'term': {'entity_id': entity_id}}
                    ]
                }
            },
            'size': 0
        })
        
        return result['hits']['total']['value']


class SnippetService:
    """Service for managing markdown snippet library."""
    
    # Predefined categories - empty, categories are user-defined
    CATEGORIES = []
    
    def __init__(self):
        self.es = ElasticsearchService()
    
    def create_snippet(self, data: Dict, user_id: str, username: str) -> Dict:
        """Create a new snippet."""
        snippet_id = secrets.token_hex(16)
        
        snippet_doc = {
            'id': snippet_id,
            'title': data.get('title', '').strip(),
            'description': data.get('description', ''),
            'content': data.get('content', ''),
            'category': data.get('category', 'other'),
            'tags': data.get('tags', []),
            'is_global': data.get('is_global', False),
            'created_by_id': user_id,
            'created_by_name': username,
            'usage_count': 0,
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('snippets', snippet_id, snippet_doc)
        return snippet_doc
    
    def get_snippet(self, snippet_id: str) -> Optional[Dict]:
        """Get a snippet by ID."""
        try:
            result = self.es.get('snippets', snippet_id)
            if result:
                snippet = result['_source']
                snippet['id'] = result['_id']
                return snippet
        except Exception:
            pass
        return None
    
    def update_snippet(self, snippet_id: str, updates: Dict, user_id: str, is_admin: bool = False) -> Optional[Dict]:
        """Update a snippet."""
        snippet = self.get_snippet(snippet_id)
        if not snippet:
            return None
        
        # Check ownership or admin for global snippets
        if snippet['created_by_id'] != user_id:
            if not is_admin:
                return None
        
        allowed_fields = ['title', 'description', 'content', 'category', 'tags', 'is_global']
        update_doc = {k: v for k, v in updates.items() if k in allowed_fields}
        update_doc['updated_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.es.update('snippets', snippet_id, {'doc': update_doc})
        return self.get_snippet(snippet_id)
    
    def delete_snippet(self, snippet_id: str, user_id: str, is_admin: bool = False) -> bool:
        """Delete a snippet."""
        snippet = self.get_snippet(snippet_id)
        if not snippet:
            return False
        
        # Check ownership or admin
        if snippet['created_by_id'] != user_id and not is_admin:
            return False
        
        self.es.delete('snippets', snippet_id)
        return True
    
    def list_snippets(self, user_id: str, page: int = 1, per_page: int = 50,
                      category: str = None, search: str = None, 
                      include_global: bool = True) -> Dict:
        """List snippets available to a user."""
        from_idx = (page - 1) * per_page
        
        # User can see their own snippets or global snippets
        query = {
            'bool': {
                'should': [
                    {'term': {'created_by_id': user_id}}
                ],
                'minimum_should_match': 1
            }
        }
        
        if include_global:
            query['bool']['should'].append({'term': {'is_global': True}})
        
        # Add filters
        if category:
            query['bool']['must'] = query['bool'].get('must', [])
            query['bool']['must'].append({'term': {'category': category}})
        
        if search:
            query['bool']['must'] = query['bool'].get('must', [])
            query['bool']['must'].append({
                'multi_match': {
                    'query': search,
                    'fields': ['title', 'description', 'content', 'tags']
                }
            })
        
        result = self.es.search('snippets', {
            'query': query,
            'sort': [
                {'usage_count': {'order': 'desc'}},
                {'updated_at': {'order': 'desc'}}
            ],
            'from': from_idx,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            snippet = hit['_source']
            snippet['id'] = hit['_id']
            items.append(snippet)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def increment_usage(self, snippet_id: str):
        """Increment the usage count of a snippet."""
        try:
            self.es.es.update(
                index=self.es._get_index_name('snippets'),
                id=snippet_id,
                body={
                    'script': {
                        'source': 'ctx._source.usage_count += 1',
                        'lang': 'painless'
                    }
                }
            )
        except Exception:
            pass
    
    def get_categories(self) -> List[Dict]:
        """Get all snippet categories with counts from Elasticsearch."""
        result = self.es.search('snippets', {
            'size': 0,
            'aggs': {
                'categories': {
                    'terms': {'field': 'category', 'size': 50}
                }
            }
        })
        
        # Return categories found in Elasticsearch, sorted by name
        categories = [
            {'name': b['key'], 'count': b['doc_count']}
            for b in result['aggregations']['categories']['buckets']
        ]
        
        # Sort by name
        return sorted(categories, key=lambda x: x['name'])
    
    def import_snippet(self, content: str, title: str, category: str,
                       user_id: str, username: str) -> Dict:
        """Import a snippet from markdown content."""
        return self.create_snippet({
            'title': title,
            'content': content,
            'category': category,
            'description': f'Imported on {datetime.utcnow().strftime("%Y-%m-%d")}',
            'is_global': False
        }, user_id, username)
    
    def export_snippet(self, snippet_id: str) -> Optional[str]:
        """Export a snippet as markdown."""
        snippet = self.get_snippet(snippet_id)
        if not snippet:
            return None
        
        # Build markdown with metadata header
        export = f"""---
title: {snippet['title']}
category: {snippet['category']}
tags: {', '.join(snippet.get('tags', []))}
created_by: {snippet['created_by_name']}
created_at: {snippet['created_at']}
---

{snippet['content']}
"""
        return export
