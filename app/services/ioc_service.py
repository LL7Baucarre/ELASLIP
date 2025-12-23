"""IOC Service for managing indicators."""

from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from app.services.elasticsearch_service import ElasticsearchService
from app.models.stix_schema import STIXIndicator
from app.utils.pattern_generator import PatternGenerator


class IOCService:
    """Service for IOC CRUD operations with deduplication."""
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.index = 'ioc'
    
    def create(self, 
               ioc_type: str, 
               value: str, 
               labels: List[str] = None,
               source: Dict = None,
               name: str = None,
               description: str = None,
               threat_level: str = None,
               confidence: str = None,
               tlp: str = None,
               campaigns: List[str] = None) -> Tuple[Dict, bool]:
        """
        Create a new IOC or update existing one with new source.
        
        Args:
            ioc_type: Type of IOC (md5, sha1, sha256, ipv4, ipv6, domain, email, url, asn, file-path, process-name, registry-key, windows-registry-key, mutex, certificate-serial)
            value: The IOC value
            labels: List of labels/tags
            source: Source information
            name: Optional indicator name
            description: Optional description
            threat_level: Optional threat level (unknown|low|medium|high|critical)
            confidence: Optional confidence level (low|medium|high|very-high)
            tlp: Optional TLP level (white|green|amber|red)
            campaigns: Optional list of related campaigns
        
        Returns:
            Tuple of (IOC dict, is_new) where is_new is False if deduplicated
        """
        # Create STIX indicator
        indicator = STIXIndicator.create(
            ioc_type=ioc_type,
            value=value,
            labels=labels,
            source=source,
            name=name,
            description=description
        )
        
        # Generate pattern hash for deduplication
        pattern_hash = PatternGenerator.get_pattern_hash(indicator.pattern)
        
        # Check for existing IOC with same pattern
        existing = self._find_by_pattern_hash(pattern_hash)
        
        if existing:
            # Add new source to existing IOC
            return self._add_source_to_existing(existing, source), False
        
        # Create new IOC
        ioc_doc = indicator.to_dict()
        ioc_doc['pattern_hash'] = pattern_hash
        ioc_doc['ioc_type'] = ioc_type
        ioc_doc['ioc_value'] = value.lower() if ioc_type in ['md5', 'sha1', 'sha256'] else value
        
        # Add threat_level if provided
        if threat_level:
            ioc_doc['threat_level'] = threat_level
        
        # Add confidence if provided
        if confidence:
            ioc_doc['confidence'] = confidence
        
        # Add TLP if provided
        if tlp:
            ioc_doc['tlp'] = tlp
        
        # Add campaigns if provided
        if campaigns:
            ioc_doc['campaigns'] = campaigns
        
        self.es.index(self.index, indicator.id, ioc_doc)
        
        # Trigger webhook
        self._trigger_webhook('ioc.created', ioc_doc)
        
        return ioc_doc, True
    
    def create_from_pattern(self,
                           pattern: str,
                           labels: List[str] = None,
                           source: Dict = None,
                           name: str = None,
                           description: str = None) -> Tuple[Dict, bool]:
        """
        Create IOC from a raw STIX pattern.
        
        Args:
            pattern: STIX pattern string
            labels: List of labels/tags
            source: Source information
            name: Optional indicator name
            description: Optional description
        
        Returns:
            Tuple of (IOC dict, is_new)
        """
        # Create STIX indicator from pattern
        indicator = STIXIndicator.from_pattern(
            pattern=pattern,
            labels=labels,
            source=source,
            name=name,
            description=description
        )
        
        # Generate pattern hash for deduplication
        pattern_hash = PatternGenerator.get_pattern_hash(indicator.pattern)
        
        # Extract IOC type and value if possible
        ioc_type, ioc_value = PatternGenerator.extract_value_from_pattern(pattern)
        
        # Check for existing IOC
        existing = self._find_by_pattern_hash(pattern_hash)
        
        if existing:
            return self._add_source_to_existing(existing, source), False
        
        # Create new IOC
        ioc_doc = indicator.to_dict()
        ioc_doc['pattern_hash'] = pattern_hash
        ioc_doc['ioc_type'] = ioc_type
        ioc_doc['ioc_value'] = ioc_value
        
        self.es.index(self.index, indicator.id, ioc_doc)
        
        self._trigger_webhook('ioc.created', ioc_doc)
        
        return ioc_doc, True
    
    def get(self, ioc_id: str) -> Optional[Dict]:
        """Get IOC by ID."""
        result = self.es.get(self.index, ioc_id)
        if result:
            doc = result['_source']
            doc['id'] = result['_id']
            return doc
        return None
    
    def update(self, ioc_id: str, updates: Dict) -> Optional[Dict]:
        """
        Update an IOC.
        
        Args:
            ioc_id: IOC ID
            updates: Fields to update (labels, name, description, threat_level, confidence, tlp, campaigns)
        
        Returns:
            Updated IOC or None if not found
        """
        existing = self.get(ioc_id)
        if not existing:
            return None
        
        # Only allow updating certain fields
        allowed_fields = ['labels', 'name', 'description', 'threat_level', 'confidence', 'tlp', 'campaigns']
        update_doc = {
            k: v for k, v in updates.items() 
            if k in allowed_fields
        }
        update_doc['modified'] = datetime.utcnow().isoformat()
        
        self.es.update(self.index, ioc_id, {'doc': update_doc})
        
        updated = self.get(ioc_id)
        self._trigger_webhook('ioc.updated', updated)
        
        return updated
    
    def delete(self, ioc_id: str) -> bool:
        """Delete an IOC."""
        existing = self.get(ioc_id)
        if not existing:
            return False
        
        result = self.es.delete(self.index, ioc_id)
        
        if result:
            self._trigger_webhook('ioc.deleted', existing)
        
        return result
    
    def list(self, 
             page: int = 1, 
             per_page: int = 20,
             ioc_type: str = None,
             labels: List[str] = None,
             source: str = None) -> Dict:
        """
        List IOCs with pagination and filters.
        
        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            ioc_type: Filter by IOC type
            labels: Filter by labels
            source: Filter by source name
        
        Returns:
            Dict with items, total, page, per_page
        """
        query = {"bool": {"must": []}}
        
        if ioc_type:
            query["bool"]["must"].append({"term": {"ioc_type": ioc_type}})
        
        if labels:
            for label in labels:
                query["bool"]["must"].append({"term": {"labels": label}})
        
        if source:
            query["bool"]["must"].append({
                "nested": {
                    "path": "sources",
                    "query": {"term": {"sources.name": source}}
                }
            })
        
        if not query["bool"]["must"]:
            query = {"match_all": {}}
        
        from_idx = (page - 1) * per_page
        
        result = self.es.search(self.index, {
            "query": query,
            "from": from_idx,
            "size": per_page,
            "sort": [{"created": {"order": "desc"}}]
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            
            # Get count of relations for this IOC
            relations = self.es.search('ioc_relations', {
                'query': {
                    'bool': {
                        'should': [
                            {'term': {'source_id': hit['_id']}},
                            {'term': {'target_id': hit['_id']}}
                        ]
                    }
                },
                'size': 0  # Only get count, no results
            })
            doc['relations_count'] = relations['hits']['total']['value']
            items.append(doc)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def get_sources(self, ioc_id: str) -> List[Dict]:
        """Get all sources for an IOC."""
        ioc = self.get(ioc_id)
        if ioc:
            return ioc.get('sources', [])
        return []
    
    def get_stats(self) -> Dict:
        """Get IOC statistics."""
        result = self.es.aggregate(self.index, {
            "by_type": {
                "terms": {"field": "ioc_type", "size": 10}
            },
            "by_label": {
                "terms": {"field": "labels", "size": 20}
            },
            "total": {
                "value_count": {"field": "id"}
            }
        })
        
        stats = {
            'total': self.es.count(self.index),
            'by_type': {},
            'by_label': {}
        }
        
        for bucket in result.get('aggregations', {}).get('by_type', {}).get('buckets', []):
            stats['by_type'][bucket['key']] = bucket['doc_count']
        
        for bucket in result.get('aggregations', {}).get('by_label', {}).get('buckets', []):
            stats['by_label'][bucket['key']] = bucket['doc_count']
        
        return stats
    
    def _find_by_pattern_hash(self, pattern_hash: str) -> Optional[Dict]:
        """Find IOC by pattern hash."""
        result = self.es.search(self.index, {
            "query": {"term": {"pattern_hash": pattern_hash}},
            "size": 1
        })
        
        if result['hits']['total']['value'] > 0:
            hit = result['hits']['hits'][0]
            doc = hit['_source']
            doc['id'] = hit['_id']
            return doc
        return None
    
    def _add_source_to_existing(self, existing: Dict, source: Dict) -> Dict:
        """Add a new source to an existing IOC."""
        if source is None:
            source = {'name': 'unknown'}
        
        new_source = {
            'name': source.get('name', 'unknown'),
            'timestamp': source.get('timestamp', datetime.utcnow().isoformat()),
            'metadata': source.get('metadata', {})
        }
        
        sources = existing.get('sources', [])
        sources.append(new_source)
        
        self.es.update(self.index, existing['id'], {
            'doc': {
                'sources': sources,
                'modified': datetime.utcnow().isoformat()
            }
        })
        
        updated = self.get(existing['id'])
        self._trigger_webhook('ioc.updated', updated)
        
        return updated
    
    def _trigger_webhook(self, event: str, data: Dict):
        """Trigger webhook for an event."""
        from app.tasks.webhook_tasks import dispatch_webhook
        try:
            dispatch_webhook.delay(event, data)
        except Exception:
            # Don't fail if webhook dispatch fails
            pass
