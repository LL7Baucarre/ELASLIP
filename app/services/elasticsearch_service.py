"""Elasticsearch Service for IOC Manager."""

import os
from typing import Dict, Any, Optional, List
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError


class ElasticsearchService:
    """Service for Elasticsearch operations."""
    
    _instance = None
    _client = None
    INDEX_PREFIX = "ioc_manager_"
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
            es_user = os.getenv('ELASTICSEARCH_USER', 'elastic')
            es_password = os.getenv('ELASTICSEARCH_PASSWORD', 'elastic123')
            
            # Create Elasticsearch client with basic auth if credentials are provided
            if es_user and es_password and 'http://' in es_url and '@' not in es_url:
                # Construct URL with credentials if not already included
                es_url = es_url.replace('http://', f'http://{es_user}:{es_password}@')
            
            self._client = Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False)
    
    @property
    def client(self) -> Elasticsearch:
        """Get Elasticsearch client."""
        return self._client
    
    def _get_index_name(self, index: str) -> str:
        """Add prefix to index name if not already present."""
        if not index.startswith(self.INDEX_PREFIX):
            return f"{self.INDEX_PREFIX}{index}"
        return index
    
    def index(self, index: str, doc_id: str, document: Dict[str, Any]) -> Dict:
        """
        Index a document.
        
        Args:
            index: Index name
            doc_id: Document ID
            document: Document data
        
        Returns:
            Elasticsearch response
        """
        return self._client.index(
            index=self._get_index_name(index),
            id=doc_id,
            document=document,
            refresh=True
        )
    
    def get(self, index: str, doc_id: str) -> Optional[Dict]:
        """
        Get a document by ID.
        
        Args:
            index: Index name
            doc_id: Document ID
        
        Returns:
            Document or None if not found
        """
        try:
            return self._client.get(index=self._get_index_name(index), id=doc_id)
        except NotFoundError:
            return None
    
    def search(self, index: str, query: Dict[str, Any], **kwargs) -> Dict:
        """
        Search for documents.
        
        Args:
            index: Index name
            query: Elasticsearch query DSL
            **kwargs: Additional search parameters
        
        Returns:
            Elasticsearch search response
        """
        return self._client.search(index=self._get_index_name(index), body=query, **kwargs)
    
    def update(self, index: str, doc_id: str, body: Dict[str, Any]) -> Dict:
        """
        Update a document.
        
        Args:
            index: Index name
            doc_id: Document ID
            body: Update body with 'doc' or 'script'
        
        Returns:
            Elasticsearch response
        """
        return self._client.update(
            index=self._get_index_name(index),
            id=doc_id,
            body=body,
            refresh=True
        )
    
    def delete(self, index: str, doc_id: str) -> bool:
        """
        Delete a document.
        
        Args:
            index: Index name
            doc_id: Document ID
        
        Returns:
            True if deleted, False if not found
        """
        try:
            self._client.delete(index=self._get_index_name(index), id=doc_id, refresh=True)
            return True
        except NotFoundError:
            return False
    
    def bulk_index(self, index: str, documents: List[Dict[str, Any]]) -> Dict:
        """
        Bulk index documents.
        
        Args:
            index: Index name
            documents: List of documents with '_id' field
        
        Returns:
            Bulk operation response
        """
        index_name = self._get_index_name(index)
        operations = []
        for doc in documents:
            doc_id = doc.pop('_id', doc.get('id'))
            operations.append({'index': {'_index': index_name, '_id': doc_id}})
            operations.append(doc)
        
        return self._client.bulk(operations=operations, refresh=True)
    
    def count(self, index: str, query: Optional[Dict[str, Any]] = None) -> int:
        """
        Count documents in an index.
        
        Args:
            index: Index name
            query: Optional query to filter documents
        
        Returns:
            Document count
        """
        body = {'query': query['query']} if query and 'query' in query else None
        result = self._client.count(index=self._get_index_name(index), body=body)
        return result['count']
    
    def exists(self, index: str, doc_id: str) -> bool:
        """
        Check if a document exists.
        
        Args:
            index: Index name
            doc_id: Document ID
        
        Returns:
            True if exists, False otherwise
        """
        return self._client.exists(index=self._get_index_name(index), id=doc_id)
    
    def aggregate(self, index: str, aggs: Dict[str, Any], query: Optional[Dict] = None) -> Dict:
        """
        Run aggregations.
        
        Args:
            index: Index name
            aggs: Aggregation definition
            query: Optional query filter
        
        Returns:
            Aggregation results
        """
        body = {'aggs': aggs, 'size': 0}
        if query:
            body['query'] = query.get('query', query)
        
        return self._client.search(index=self._get_index_name(index), body=body)
    
    def refresh(self, index: str):
        """Refresh an index."""
        self._client.indices.refresh(index=self._get_index_name(index))
