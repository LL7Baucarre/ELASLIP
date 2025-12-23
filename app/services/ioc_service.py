"""IOC Service for managing indicators."""

from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from app.services.elasticsearch_service import ElasticsearchService
from app.services.cache_service import CacheService
from app.services.audit_service import AuditService
from app.models.stix_schema import STIXIndicator
from app.utils.pattern_generator import PatternGenerator


class IOCService:
    """Service for IOC CRUD operations with deduplication."""
    
    # Risk score weights and mappings
    THREAT_LEVEL_SCORES = {
        'unknown': 0,
        'low': 20,
        'medium': 50,
        'high': 80,
        'critical': 100
    }
    
    CONFIDENCE_SCORES = {
        'low': 25,
        'medium': 50,
        'high': 75,
        'very-high': 100
    }
    
    TLP_SCORES = {
        'white': 25,    # Low sensitivity = lower risk priority
        'green': 50,
        'amber': 75,
        'red': 100      # High sensitivity = higher risk priority
    }
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.cache = CacheService()
        self.audit = AuditService()
        self.index = 'ioc'
    
    @staticmethod
    def _sanitize_stix_indicator(ioc: Dict) -> Dict:
        """
        Sanitize IOC document to strict STIX 2.1 compliance.
        
        This method:
        1. Removes all enrichment_* fields from root (they should be in x_enrichment)
        2. Ensures timestamps have UTC 'Z' suffix
        3. Removes invalid/duplicate fields
        4. Groups enrichment data into x_enrichment object
        
        Args:
            ioc: Raw IOC document from Elasticsearch
        
        Returns:
            Sanitized STIX 2.1 compliant document
        """
        if not isinstance(ioc, dict):
            return ioc
        
        # STIX 2.1 Indicator valid properties
        STIX_2_1_PROPERTIES = {
            # Core properties
            'type', 'id', 'spec_version', 'created', 'modified',
            # Indicator-specific
            'pattern', 'pattern_type', 'valid_from', 'valid_until',
            'indicator_types', 'confidence',
            # Common properties
            'created_by_ref', 'revoked', 'labels', 'name', 'description',
            'object_marking_refs', 'marking_definitions', 'external_references',
            'granular_markings',
            # Custom STIX properties (with x_ prefix)
            'x_metadata', 'x_enrichment'
        }
        
        sanitized = {}
        enrichment_fields = {}
        
        for key, value in ioc.items():
            # Skip enrichment_* fields at root - they go to x_enrichment
            if key.startswith('enrichment_'):
                enrichment_fields[key.replace('enrichment_', '')] = value
                continue
            
            # Skip invalid root-level custom fields (not STIX-compliant)
            if key in ['risk_score', 'current_version', 'threat_level', 'tlp', 
                      'campaigns', 'status', 'asn', 'country', 'ioc_type', 'ioc_value',
                      'pattern_hash', 'sources']:
                # These go to x_metadata, not root
                continue
            
            # Keep only valid STIX properties
            if key in STIX_2_1_PROPERTIES:
                # Fix timestamp format - ensure UTC 'Z' suffix
                if key in ['created', 'modified'] and isinstance(value, str):
                    # Remove milliseconds if present and ensure Z suffix
                    value = IOCService._ensure_timestamp_format(value)
                
                sanitized[key] = value
        
        # Ensure x_metadata exists and is valid, preserve from original
        if 'x_metadata' in ioc and isinstance(ioc['x_metadata'], dict):
            sanitized['x_metadata'] = ioc['x_metadata'].copy()
        else:
            sanitized['x_metadata'] = {}
        
        # If we found enrichment fields, group them in x_enrichment
        if enrichment_fields:
            # Create or update x_enrichment
            if 'x_enrichment' not in sanitized:
                sanitized['x_enrichment'] = {}
            
            # Ensure x_enrichment is a dict
            if not isinstance(sanitized['x_enrichment'], dict):
                sanitized['x_enrichment'] = {}
            
            # Create api_results array if it doesn't exist
            if 'api_results' not in sanitized['x_enrichment']:
                sanitized['x_enrichment']['api_results'] = []
            
            # Create a single result object with all enrichment data
            api_result = {}
            for key, value in enrichment_fields.items():
                api_result[key] = value
            
            # Add or update the first result
            if isinstance(sanitized['x_enrichment']['api_results'], list):
                if len(sanitized['x_enrichment']['api_results']) > 0:
                    # Merge with existing first result
                    sanitized['x_enrichment']['api_results'][0].update(api_result)
                else:
                    # Add new result
                    sanitized['x_enrichment']['api_results'].append(api_result)
        else:
            # Preserve x_enrichment if it exists
            if 'x_enrichment' in ioc and isinstance(ioc['x_enrichment'], dict):
                sanitized['x_enrichment'] = ioc['x_enrichment'].copy()
        
        return sanitized
    
    @staticmethod
    def _ensure_timestamp_format(timestamp: str) -> str:
        """
        Ensure timestamp has proper ISO 8601 + UTC format with 'Z' suffix.
        
        Converts formats like:
        - 2025-12-23T22:07:20.198861 -> 2025-12-23T22:07:20.198861Z
        - 2025-12-23T22:07:20.283791 -> 2025-12-23T22:07:20.283791Z
        - 2025-12-23T22:07:20Z -> 2025-12-23T22:07:20Z (already good)
        """
        if not isinstance(timestamp, str):
            return timestamp
        
        # Already has Z suffix
        if timestamp.endswith('Z'):
            return timestamp
        
        # Has timezone offset (+00:00 or -05:00)
        if '+' in timestamp or (timestamp.count('-') > 2):
            # Extract just the datetime part before timezone
            base = timestamp.split('+')[0].split('-')[0] if '+' in timestamp else timestamp.split('+')[0]
            return base + 'Z'
        
        # No timezone indicator - add Z
        return timestamp + 'Z'

    
    @classmethod
    def _convert_confidence_to_int(cls, confidence: str) -> Optional[int]:
        """Convert confidence string to STIX 2.1 integer (0-100)."""
        if confidence is None:
            return None
        if isinstance(confidence, int):
            return confidence
        # Map text confidence to integer
        return cls.CONFIDENCE_SCORES.get(confidence.lower() if isinstance(confidence, str) else None)
    
    @classmethod
    def calculate_risk_score(cls, threat_level: str = None, confidence: str = None, tlp: str = None) -> int:
        """
        Calculate composite risk score from threat_level, confidence, and TLP.
        
        Formula: (threat_level * 0.45) + (confidence * 0.35) + (tlp * 0.20)
        
        Returns:
            Integer score from 0-100
        """
        threat_score = cls.THREAT_LEVEL_SCORES.get(threat_level, 0)
        confidence_score = cls.CONFIDENCE_SCORES.get(confidence, 0)
        tlp_score = cls.TLP_SCORES.get(tlp, 0)
        
        # Weighted composite score
        composite = (threat_score * 0.45) + (confidence_score * 0.35) + (tlp_score * 0.20)
        
        return int(round(composite))
    
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
               campaigns: List[str] = None,
               valid_from: str = None,
               valid_until: str = None,
               user_id: str = None,
               username: str = None) -> Tuple[Dict, bool]:
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
            user_id: User ID who created this IOC
            username: Username who created this IOC
        
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
        
        # Create new IOC with STIX 2.1 compliant structure
        # Use to_dict_with_metadata to include custom properties with x_ prefix
        ioc_doc = indicator.to_dict_with_metadata(
            ioc_type=ioc_type,
            ioc_value=value.lower() if ioc_type in ['md5', 'sha1', 'sha256'] else value,
            pattern_hash=pattern_hash,
            threat_level=threat_level,
            confidence=self._convert_confidence_to_int(confidence),  # Convert to 0-100
            tlp=tlp,
            campaigns=campaigns,
            risk_score=self.calculate_risk_score(threat_level, confidence, tlp),
            status='active',
            current_version=1,
            user_id=user_id,
            username=username
        )
        
        self.es.index(self.index, indicator.id, ioc_doc)
        
        # Create initial version snapshot (with metadata)
        self._create_version_snapshot(indicator.id, ioc_doc, None, 'system')
        
        # Log to audit trail
        try:
            self.audit.log(
                action='create',
                entity_type='ioc',
                entity_id=indicator.id,
                entity_name=ioc_doc.get('name', value),
                changes={'created': True},
                user_id='system',
                username='system'
            )
        except Exception:
            pass
        
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
            # Sanitize to STIX 2.1 compliance
            doc = self._sanitize_stix_indicator(doc)
            return doc
        return None
    
    def update(self, ioc_id: str, updates: Dict, user_id: str = None, username: str = None) -> Optional[Dict]:
        """
        Update an IOC with versioning support.
        
        Args:
            ioc_id: IOC ID
            updates: Fields to update (labels, name, description, threat_level, confidence, tlp, campaigns, valid_from, valid_until, status, x_enrichment, x_metadata)
            user_id: User ID making the update (for audit trail)
            username: Username making the update
        
        Returns:
            Updated IOC or None if not found
        """
        existing = self.get(ioc_id)
        if not existing:
            return None
        
        # Allow updating both standard fields and custom STIX fields with x_ prefix
        # STIX 2.1 compliant: only x_* and specific root properties are allowed
        allowed_fields = [
            'labels', 'name', 'description', 'valid_from', 'valid_until',
            'x_enrichment', 'x_metadata'  # STIX 2.1 custom properties
        ]
        update_doc = {}
        for k, v in updates.items():
            # REJECT enrichment_* fields at root (they violate STIX 2.1)
            if k.startswith('enrichment_'):
                # Skip these - they should go in x_enrichment
                continue
            
            # Allow only STIX-compliant fields
            if k in allowed_fields or k.startswith('x_'):
                update_doc[k] = v
        
        # Ensure modified timestamp has Z suffix
        modified_ts = datetime.utcnow().isoformat() + 'Z'
        update_doc['modified'] = modified_ts
        
        # Recalculate risk score if relevant fields changed
        threat_level = updates.get('threat_level', existing.get('threat_level'))
        confidence = updates.get('confidence', existing.get('confidence'))
        tlp = updates.get('tlp', existing.get('tlp'))
        update_doc['risk_score'] = self.calculate_risk_score(threat_level, confidence, tlp)
        
        # Increment version
        current_version = existing.get('current_version', 1)
        new_version = current_version + 1
        update_doc['current_version'] = new_version
        
        # Create version snapshot with the NEW version number
        snapshot_for_version = existing.copy()
        snapshot_for_version['current_version'] = new_version
        self._create_version_snapshot(ioc_id, snapshot_for_version, updates, user_id, username)
        
        self.es.update(self.index, ioc_id, {'doc': update_doc})
        
        updated = self.get(ioc_id)
        
        # Log to audit trail
        try:
            # Build meaningful entity name
            entity_name = updated.get('name') or updated.get('value') or f"{updated.get('type', 'IOC')}"
            self.audit.log(
                action='update',
                entity_type='ioc',
                entity_id=ioc_id,
                entity_name=entity_name,
                changes=updates,
                user_id=user_id,
                username=username
            )
        except Exception:
            pass
        
        self._trigger_webhook('ioc.updated', updated)
        
        return updated
    
    def delete(self, ioc_id: str) -> bool:
        """Delete an IOC."""
        existing = self.get(ioc_id)
        if not existing:
            return False
        
        result = self.es.delete(self.index, ioc_id)
        
        if result:
            # Log to audit trail
            try:
                # Build meaningful entity name
                entity_name = existing.get('name') or existing.get('value') or f"{existing.get('type', 'IOC')}"
                self.audit.log(
                    action='delete',
                    entity_type='ioc',
                    entity_id=ioc_id,
                    entity_name=entity_name,
                    changes={'deleted': True},
                    user_id='system',
                    username='system'
                )
            except Exception:
                pass
            
            self._trigger_webhook('ioc.deleted', existing)
        
        return result
    
    def list(self, 
             page: int = 1, 
             per_page: int = 20,
             ioc_type: str = None,
             labels: List[str] = None,
             tlp: str = None,
             threat_level: str = None,
             confidence: str = None,
             campaigns: str = None,
             source: str = None) -> Dict:
        """
        List IOCs with pagination and filters.
        
        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            ioc_type: Filter by IOC type
            labels: Filter by labels
            tlp: Filter by TLP level
            threat_level: Filter by threat level
            confidence: Filter by confidence level
            campaigns: Filter by campaigns
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
        
        if tlp:
            query["bool"]["must"].append({"term": {"tlp": tlp}})
        
        if threat_level:
            query["bool"]["must"].append({"term": {"threat_level": threat_level}})
        
        if confidence:
            query["bool"]["must"].append({"term": {"confidence": confidence}})
        
        if campaigns:
            query["bool"]["must"].append({"term": {"campaigns": campaigns}})
        
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
            
            # Sanitize to STIX 2.1 compliance
            doc = self._sanitize_stix_indicator(doc)
            
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
        """Get IOC statistics with caching."""
        # Try to get from cache first
        cached = self.cache.get_cached_stats()
        if cached:
            return cached
        
        result = self.es.aggregate(self.index, {
            "by_type": {
                "terms": {"field": "ioc_type", "size": 10}
            },
            "by_label": {
                "terms": {"field": "labels", "size": 20}
            },
            "by_tlp": {
                "terms": {"field": "tlp", "size": 5}
            },
            "by_threat_level": {
                "terms": {"field": "threat_level", "size": 5}
            },
            "by_status": {
                "terms": {"field": "status", "size": 5}
            },
            "avg_risk_score": {
                "avg": {"field": "risk_score"}
            },
            "total": {
                "value_count": {"field": "id"}
            }
        })
        
        stats = {
            'total': self.es.count(self.index),
            'by_type': {},
            'by_label': {},
            'by_tlp': {},
            'by_threat_level': {},
            'by_status': {},
            'avg_risk_score': 0
        }
        
        aggs = result.get('aggregations', {})
        
        for bucket in aggs.get('by_type', {}).get('buckets', []):
            stats['by_type'][bucket['key']] = bucket['doc_count']
        
        for bucket in aggs.get('by_label', {}).get('buckets', []):
            stats['by_label'][bucket['key']] = bucket['doc_count']
        
        for bucket in aggs.get('by_tlp', {}).get('buckets', []):
            stats['by_tlp'][bucket['key']] = bucket['doc_count']
        
        for bucket in aggs.get('by_threat_level', {}).get('buckets', []):
            stats['by_threat_level'][bucket['key']] = bucket['doc_count']
        
        for bucket in aggs.get('by_status', {}).get('buckets', []):
            stats['by_status'][bucket['key']] = bucket['doc_count']
        
        stats['avg_risk_score'] = round(aggs.get('avg_risk_score', {}).get('value', 0) or 0, 1)
        
        # Cache the results
        self.cache.cache_stats(stats)
        
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
        
        # Get sources and metadata from x_metadata
        x_metadata = existing.get('x_metadata', {})
        sources = x_metadata.get('sources', [])
        
        # Check if this source already exists (avoid duplicates)
        source_exists = any(
            s.get('name') == new_source['name'] and 
            s.get('metadata') == new_source['metadata']
            for s in sources
        )
        
        if not source_exists:
            sources.append(new_source)
            x_metadata['sources'] = sources
            
            # Update external_references in STIX object
            external_refs = []
            for s in sources:
                ref = {
                    'source_name': s.get('name', 'unknown'),
                }
                if s.get('metadata'):
                    ref['description'] = 'Metadata from source'
                external_refs.append(ref)
            
            self.es.update(self.index, existing['id'], {
                'doc': {
                    'x_metadata': x_metadata,
                    'external_references': external_refs,
                    'modified': datetime.utcnow().isoformat() + 'Z'
                }
            })
        
        updated = self.get(existing['id'])
        self._trigger_webhook('ioc.updated', updated)
        
        return updated
    
    def _trigger_webhook(self, event: str, data: Dict):
        """Trigger webhook for an event and invalidate cache."""
        from app.tasks.webhook_tasks import dispatch_webhook
        try:
            dispatch_webhook.delay(event, data)
        except Exception:
            # Don't fail if webhook dispatch fails
            pass
        
        # Invalidate cache on any IOC change
        try:
            self.cache.invalidate_ioc_cache()
        except Exception:
            pass
    
    def _create_version_snapshot(self, ioc_id: str, snapshot: Dict, changes: Dict = None, 
                                  user_id: str = None, username: str = None):
        """Create a version snapshot for an IOC."""
        import secrets
        
        version_id = secrets.token_hex(16)
        version_number = snapshot.get('current_version', 1)
        
        version_doc = {
            'id': version_id,
            'ioc_id': ioc_id,
            'version_number': version_number,
            'snapshot': snapshot,
            'changes': changes,
            'modified_by': username or user_id or 'system',
            'modified_by_username': username or 'system',
            'modified_at': datetime.utcnow().isoformat() + 'Z',
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.es.index('ioc_versions', version_id, version_doc)
    
    def get_versions(self, ioc_id: str, page: int = 1, per_page: int = 20) -> Dict:
        """Get version history for an IOC."""
        from_idx = (page - 1) * per_page
        
        result = self.es.search('ioc_versions', {
            'query': {'term': {'ioc_id': ioc_id}},
            'sort': [{'version_number': {'order': 'desc'}}],
            'from': from_idx,
            'size': per_page
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return {
            'items': items,
            'total': result['hits']['total']['value'],
            'page': page,
            'per_page': per_page
        }
    
    def restore_version(self, ioc_id: str, version_number: int, user_id: str = None, username: str = None) -> Optional[Dict]:
        """Restore an IOC to a previous version."""
        # Find the version
        result = self.es.search('ioc_versions', {
            'query': {
                'bool': {
                    'must': [
                        {'term': {'ioc_id': ioc_id}},
                        {'term': {'version_number': version_number}}
                    ]
                }
            },
            'size': 1
        })
        
        if result['hits']['total']['value'] == 0:
            return None
        
        version = result['hits']['hits'][0]['_source']
        snapshot = version.get('snapshot', {})
        
        # Get current IOC to create snapshot
        current = self.get(ioc_id)
        if not current:
            return None
        
        # Create snapshot before restore
        self._create_version_snapshot(ioc_id, current, {'action': 'restore', 'from_version': version_number}, user_id, username)
        
        # Prepare update with snapshot data
        restore_fields = ['labels', 'name', 'description', 'threat_level', 'confidence', 'tlp', 'campaigns', 'valid_from', 'valid_until']
        update_doc = {k: snapshot.get(k) for k in restore_fields if k in snapshot}
        update_doc['modified'] = datetime.utcnow().isoformat()
        update_doc['current_version'] = current.get('current_version', 1) + 1
        
        # Recalculate risk score
        update_doc['risk_score'] = self.calculate_risk_score(
            snapshot.get('threat_level'),
            snapshot.get('confidence'),
            snapshot.get('tlp')
        )
        
        self.es.update(self.index, ioc_id, {'doc': update_doc})
        
        return self.get(ioc_id)
    
    # Bulk Operations
    def bulk_update(self, ioc_ids: List[str], updates: Dict, user_id: str = None, username: str = None) -> Dict:
        """
        Bulk update multiple IOCs.
        
        Args:
            ioc_ids: List of IOC IDs to update
            updates: Fields to update
            user_id: User making the update
            username: Username for audit trail
        
        Returns:
            Dict with success count and errors
        """
        success = 0
        errors = []
        
        for ioc_id in ioc_ids:
            try:
                result = self.update(ioc_id, updates, user_id, username)
                if result:
                    success += 1
                else:
                    errors.append({'id': ioc_id, 'error': 'IOC not found'})
            except Exception as e:
                errors.append({'id': ioc_id, 'error': str(e)})
        
        return {
            'success': success,
            'failed': len(errors),
            'errors': errors
        }
    
    def bulk_delete(self, ioc_ids: List[str], user_id: str = 'system', username: str = 'system') -> Dict:
        """
        Bulk delete multiple IOCs.
        
        Args:
            ioc_ids: List of IOC IDs to delete
            user_id: User ID performing the deletion
            username: Username performing the deletion
        
        Returns:
            Dict with success count and errors
        """
        success = 0
        errors = []
        
        for ioc_id in ioc_ids:
            try:
                existing = self.get(ioc_id)
                if not existing:
                    errors.append({'id': ioc_id, 'error': 'IOC not found'})
                    continue
                
                result = self.es.delete(self.index, ioc_id)
                if result:
                    # Log to audit trail
                    try:
                        # Build meaningful entity name
                        entity_name = existing.get('name') or existing.get('value') or f"{existing.get('type', 'IOC')}"
                        self.audit.log(
                            action='delete',
                            entity_type='ioc',
                            entity_id=ioc_id,
                            entity_name=entity_name,
                            changes={'deleted': True},
                            user_id=user_id,
                            username=username
                        )
                    except Exception:
                        pass
                    
                    self._trigger_webhook('ioc.deleted', existing)
                    success += 1
                else:
                    errors.append({'id': ioc_id, 'error': 'Failed to delete'})
            except Exception as e:
                errors.append({'id': ioc_id, 'error': str(e)})
        
        return {
            'success': success,
            'failed': len(errors),
            'errors': errors
        }
    
    def bulk_export(self, ioc_ids: List[str] = None, filters: Dict = None, format: str = 'json') -> List[Dict]:
        """
        Export IOCs in specified format.
        
        Args:
            ioc_ids: Specific IOC IDs to export (optional)
            filters: Filter criteria if no IDs specified
            format: Export format (json, stix, csv)
        
        Returns:
            List of IOC documents
        """
        if ioc_ids:
            iocs = []
            for ioc_id in ioc_ids:
                ioc = self.get(ioc_id)
                if ioc:
                    iocs.append(ioc)
            return iocs
        
        # Export with filters
        query = {"bool": {"must": []}}
        
        if filters:
            if filters.get('type'):
                query["bool"]["must"].append({"term": {"ioc_type": filters['type']}})
            if filters.get('tlp'):
                query["bool"]["must"].append({"term": {"tlp": filters['tlp']}})
            if filters.get('threat_level'):
                query["bool"]["must"].append({"term": {"threat_level": filters['threat_level']}})
            if filters.get('status'):
                query["bool"]["must"].append({"term": {"status": filters['status']}})
        
        if not query["bool"]["must"]:
            query = {"match_all": {}}
        
        result = self.es.search(self.index, {
            "query": query,
            "size": 10000  # Max export size
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return items
    
    # Expiration Management
    def get_expired_iocs(self) -> List[Dict]:
        """Get all IOCs that have expired (valid_until < now)."""
        now = datetime.utcnow().isoformat()
        
        result = self.es.search(self.index, {
            'query': {
                'bool': {
                    'must': [
                        {'range': {'valid_until': {'lt': now}}},
                        {'term': {'status': 'active'}}
                    ]
                }
            },
            'size': 1000
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return items
    
    def get_expiring_soon(self, days: int = 7) -> List[Dict]:
        """Get IOCs expiring within specified days."""
        from datetime import timedelta
        
        now = datetime.utcnow()
        future = (now + timedelta(days=days)).isoformat()
        now_str = now.isoformat()
        
        result = self.es.search(self.index, {
            'query': {
                'bool': {
                    'must': [
                        {'range': {'valid_until': {'gte': now_str, 'lte': future}}},
                        {'term': {'status': 'active'}}
                    ]
                }
            },
            'size': 1000
        })
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        
        return items
    
    def archive_expired_iocs(self) -> Dict:
        """Archive all expired IOCs by changing their status."""
        expired = self.get_expired_iocs()
        archived = 0
        
        for ioc in expired:
            try:
                self.es.update(self.index, ioc['id'], {
                    'doc': {
                        'status': 'expired',
                        'modified': datetime.utcnow().isoformat()
                    }
                })
                archived += 1
                self._trigger_webhook('ioc.expired', ioc)
            except Exception:
                pass
        
        return {
            'archived': archived,
            'total_expired': len(expired)
        }
