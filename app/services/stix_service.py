# -*- coding: utf-8 -*-
"""
STIX 2.1 Object Service
Handles creation, retrieval, update and deletion of all STIX Domain Objects (SDO)
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from flask import current_app

from app.services.elasticsearch_service import ElasticsearchService


class STIXService:
    """Service for managing STIX 2.1 Domain Objects in Elasticsearch"""
    
    STIX_OBJECTS_INDEX = "elaslip_stix_objects"
    STIX_RELATIONSHIPS_INDEX = "elaslip_stix_relationships"
    
    # STIX 2.1 SDO Types with their specific required/optional fields
    SDO_TYPES = {
        "indicator": {
            "required": ["pattern", "pattern_type", "valid_from"],
            "optional": ["pattern_version", "valid_until", "indicator_types", "name", "description", 
                        "x_ioc_type", "x_ioc_value", "x_threat_level", "x_tlp", "x_response_actions"]
        },
        "malware": {
            "required": ["is_family"],
            "optional": ["name", "description", "malware_types", "aliases", "first_seen", "last_seen",
                        "operating_system_refs", "architecture_execution_envs", "implementation_languages",
                        "capabilities", "sample_refs", "kill_chain_phases"]
        },
        "threat-actor": {
            "required": ["name"],
            "optional": ["description", "threat_actor_types", "aliases", "first_seen", "last_seen",
                        "roles", "goals", "sophistication", "resource_level", "primary_motivation",
                        "secondary_motivations", "personal_motivations"]
        },
        "attack-pattern": {
            "required": ["name"],
            "optional": ["description", "aliases", "kill_chain_phases", "external_references"]
        },
        "campaign": {
            "required": ["name"],
            "optional": ["description", "aliases", "first_seen", "last_seen", "objective"]
        },
        "tool": {
            "required": ["name"],
            "optional": ["description", "tool_types", "aliases", "kill_chain_phases", "tool_version"]
        },
        "vulnerability": {
            "required": ["name"],
            "optional": ["description", "external_references"]
        },
        "infrastructure": {
            "required": ["name"],
            "optional": ["description", "infrastructure_types", "aliases", "first_seen", "last_seen",
                        "kill_chain_phases"]
        },
        "intrusion-set": {
            "required": ["name"],
            "optional": ["description", "aliases", "first_seen", "last_seen", "goals",
                        "resource_level", "primary_motivation", "secondary_motivations"]
        },
        "identity": {
            "required": ["name"],
            "optional": ["description", "identity_class", "sectors", "contact_information"]
        },
        "location": {
            "required": [],  # At least one of: region, country, or lat/long
            "optional": ["name", "description", "latitude", "longitude", "precision",
                        "region", "country", "administrative_area", "city", "street_address", "postal_code"]
        },
        "course-of-action": {
            "required": ["name"],
            "optional": ["description", "action_type", "os_execution_envs", "action_bin"]
        },
        "observed-data": {
            "required": ["first_observed", "last_observed", "number_observed"],
            "optional": ["objects", "object_refs"]
        },
        "report": {
            "required": ["name", "published"],
            "optional": ["description", "report_types", "object_refs"]
        },
        "grouping": {
            "required": ["context"],
            "optional": ["name", "description", "object_refs"]
        },
        "note": {
            "required": ["content", "object_refs"],
            "optional": ["abstract", "authors"]
        },
        "opinion": {
            "required": ["opinion", "object_refs"],
            "optional": ["explanation", "authors"]
        },
        "malware-analysis": {
            "required": ["product", "result"],
            "optional": ["analysis_engine_version", "analysis_definition_version",
                        "submitted", "analysis_started", "analysis_ended"]
        }
    }
    
    # STIX 2.1 Relationship Types
    RELATIONSHIP_TYPES = [
        "uses", "targets", "attributed-to", "mitigates", "indicates",
        "derived-from", "related-to", "located-at", "communicates-with",
        "authored-by", "has", "delivers", "variant-of", "drops", "hosts",
        "downloads", "compromises", "exploits", "impersonates", "investigates",
        "originates-from", "controls", "beacons-to", "exfiltrates-to"
    ]
    
    @classmethod
    def create_sdo(cls, sdo_type: str, data: Dict[str, Any], 
                   user_id: Optional[str] = None, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new STIX Domain Object
        
        Args:
            sdo_type: The STIX object type (indicator, malware, threat-actor, etc.)
            data: The object data (name, description, type-specific fields)
            user_id: Optional user ID who created this object
            username: Optional username who created this object
            
        Returns:
            The created STIX object with its generated ID
        """
        if sdo_type not in cls.SDO_TYPES:
            raise ValueError(f"Unsupported SDO type: {sdo_type}")
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stix_id = f"{sdo_type}--{uuid.uuid4()}"
        
        # Build the STIX object
        stix_object = {
            "id": stix_id,
            "type": sdo_type,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
        }
        
        # Add common optional fields
        common_fields = ["name", "description", "labels", "confidence", "external_references",
                        "created_by_ref", "revoked", "lang", "object_marking_refs", "granular_markings"]
        for field in common_fields:
            if field in data and data[field] is not None:
                stix_object[field] = data[field]
        
        # Add type-specific fields
        type_spec = cls.SDO_TYPES[sdo_type]
        for field in type_spec["required"] + type_spec["optional"]:
            if field in data and data[field] is not None:
                stix_object[field] = data[field]
        
        # Add ELASLIP metadata
        if user_id:
            stix_object["x_elaslip_created_by_user_id"] = user_id
        if username:
            stix_object["x_elaslip_created_by_username"] = username
            
        # For indicators, generate pattern hash for deduplication
        if sdo_type == "indicator" and "pattern" in data:
            import hashlib
            pattern_hash = hashlib.sha256(data["pattern"].encode()).hexdigest()
            stix_object["x_pattern_hash"] = pattern_hash
        
        # Index in Elasticsearch
        es = ElasticsearchService().client
        es.index(
            index=cls.STIX_OBJECTS_INDEX,
            id=stix_id,
            document=stix_object,
            refresh=True
        )
        
        return stix_object
    
    @classmethod
    def get_sdo(cls, stix_id: str) -> Optional[Dict[str, Any]]:
        """Get a STIX object by ID"""
        es = ElasticsearchService().client
        try:
            result = es.get(index=cls.STIX_OBJECTS_INDEX, id=stix_id)
            return result.get("_source")
        except Exception:
            return None
    
    @classmethod
    def update_sdo(cls, stix_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a STIX object"""
        es = ElasticsearchService().client
        
        # Get current object
        current = cls.get_sdo(stix_id)
        if not current:
            return None
        
        # Update modified timestamp
        updates["modified"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Merge updates
        for key, value in updates.items():
            if value is not None:
                current[key] = value
        
        # Re-index
        es.index(
            index=cls.STIX_OBJECTS_INDEX,
            id=stix_id,
            document=current,
            refresh=True
        )
        
        return current
    
    @classmethod
    def delete_sdo(cls, stix_id: str) -> bool:
        """Delete a STIX object and its relationships"""
        es = ElasticsearchService().client
        
        try:
            # Delete the object
            es.delete(index=cls.STIX_OBJECTS_INDEX, id=stix_id, refresh=True)
            
            # Delete related relationships
            es.delete_by_query(
                index=cls.STIX_RELATIONSHIPS_INDEX,
                body={
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"source_ref": stix_id}},
                                {"term": {"target_ref": stix_id}}
                            ]
                        }
                    }
                },
                refresh=True
            )
            
            return True
        except Exception:
            return False
    
    @classmethod
    def list_sdos(cls, sdo_type: Optional[str] = None, 
                  page: int = 1, size: int = 20,
                  search: Optional[str] = None,
                  sort_by: str = "modified", sort_order: str = "desc") -> Dict[str, Any]:
        """
        List STIX objects with pagination and filtering
        
        Args:
            sdo_type: Filter by object type (optional)
            page: Page number (1-based)
            size: Page size
            search: Search term for name/description
            sort_by: Field to sort by
            sort_order: asc or desc
            
        Returns:
            Dict with items, total, page, size
        """
        es = ElasticsearchService().client
        
        query = {"bool": {"must": []}}
        
        if sdo_type:
            query["bool"]["must"].append({"term": {"type": sdo_type}})
        
        if search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": search,
                    "fields": ["name^3", "description", "pattern", "x_ioc_value"]
                }
            })
        
        if not query["bool"]["must"]:
            query = {"match_all": {}}
        
        from_idx = (page - 1) * size
        
        try:
            result = es.search(
                index=cls.STIX_OBJECTS_INDEX,
                body={
                    "query": query,
                    "from": from_idx,
                    "size": size,
                    "sort": [{sort_by: {"order": sort_order}}]
                }
            )
            
            items = [hit["_source"] for hit in result["hits"]["hits"]]
            total = result["hits"]["total"]["value"] if isinstance(result["hits"]["total"], dict) else result["hits"]["total"]
            
            return {
                "items": items,
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size
            }
        except Exception as e:
            current_app.logger.error(f"Error listing SDOs: {e}")
            return {"items": [], "total": 0, "page": page, "size": size, "pages": 0}
    
    @classmethod
    def create_relationship(cls, source_ref: str, target_ref: str, 
                           relationship_type: str,
                           description: Optional[str] = None,
                           start_time: Optional[str] = None,
                           stop_time: Optional[str] = None,
                           user_id: Optional[str] = None,
                           username: Optional[str] = None) -> Dict[str, Any]:
        """Create a STIX relationship between two objects"""
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        rel_id = f"relationship--{uuid.uuid4()}"
        
        relationship = {
            "id": rel_id,
            "type": "relationship",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref
        }
        
        if description:
            relationship["description"] = description
        if start_time:
            relationship["start_time"] = start_time
        if stop_time:
            relationship["stop_time"] = stop_time
        if user_id:
            relationship["x_elaslip_created_by_user_id"] = user_id
        if username:
            relationship["x_elaslip_created_by_username"] = username
        
        es = ElasticsearchService().client
        es.index(
            index=cls.STIX_RELATIONSHIPS_INDEX,
            id=rel_id,
            document=relationship,
            refresh=True
        )
        
        return relationship
    
    @classmethod
    def get_relationships(cls, stix_id: str, 
                          direction: str = "both") -> List[Dict[str, Any]]:
        """
        Get all relationships for a STIX object
        
        Args:
            stix_id: The STIX object ID
            direction: "source" (outgoing), "target" (incoming), or "both"
            
        Returns:
            List of relationships
        """
        es = ElasticsearchService().client
        
        if direction == "source":
            query = {"term": {"source_ref": stix_id}}
        elif direction == "target":
            query = {"term": {"target_ref": stix_id}}
        else:
            query = {
                "bool": {
                    "should": [
                        {"term": {"source_ref": stix_id}},
                        {"term": {"target_ref": stix_id}}
                    ]
                }
            }
        
        try:
            result = es.search(
                index=cls.STIX_RELATIONSHIPS_INDEX,
                body={"query": query, "size": 500}
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []
    
    @classmethod
    def delete_relationship(cls, rel_id: str) -> bool:
        """Delete a relationship by ID"""
        es = ElasticsearchService().client
        try:
            es.delete(index=cls.STIX_RELATIONSHIPS_INDEX, id=rel_id, refresh=True)
            return True
        except Exception:
            return False
    
    @classmethod
    def get_related_objects(cls, stix_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Get related objects and relationships for a STIX object
        
        Returns:
            Tuple of (related_objects, relationships)
        """
        relationships = cls.get_relationships(stix_id)
        
        if not relationships:
            return [], []
        
        # Collect all related object IDs
        related_ids = set()
        for rel in relationships:
            if rel["source_ref"] != stix_id:
                related_ids.add(rel["source_ref"])
            if rel["target_ref"] != stix_id:
                related_ids.add(rel["target_ref"])
        
        # Fetch related objects
        related_objects = []
        for rid in related_ids:
            obj = cls.get_sdo(rid)
            if obj:
                related_objects.append(obj)
        
        return related_objects, relationships
    
    @classmethod
    def export_bundle(cls, stix_id: str) -> Dict[str, Any]:
        """
        Export a STIX object with all its relationships as a STIX 2.1 Bundle
        """
        main_object = cls.get_sdo(stix_id)
        if not main_object:
            return None
        
        related_objects, relationships = cls.get_related_objects(stix_id)
        
        bundle_objects = [main_object] + related_objects + relationships
        
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": bundle_objects
        }
    
    @classmethod
    def search_sdos(cls, query_string: str, sdo_types: Optional[List[str]] = None,
                    size: int = 50) -> List[Dict[str, Any]]:
        """
        Search STIX objects by query string
        
        Args:
            query_string: Search string
            sdo_types: Optional list of object types to filter
            size: Maximum results
            
        Returns:
            List of matching objects
        """
        es = ElasticsearchService().client
        
        query = {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": query_string,
                            "fields": ["name^3", "description", "pattern", "x_ioc_value", "labels"]
                        }
                    }
                ]
            }
        }
        
        if sdo_types:
            query["bool"]["filter"] = [{"terms": {"type": sdo_types}}]
        
        try:
            result = es.search(
                index=cls.STIX_OBJECTS_INDEX,
                body={"query": query, "size": size}
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            current_app.logger.error(f"Error searching SDOs: {e}")
            return []
    
    @classmethod
    def get_available_objects_for_linking(cls, exclude_id: Optional[str] = None,
                                          search: Optional[str] = None,
                                          size: int = 100) -> List[Dict[str, Any]]:
        """
        Get available STIX objects for linking (to create relationships)
        
        Args:
            exclude_id: Exclude this object from results
            search: Optional search filter
            size: Maximum results
            
        Returns:
            List of objects with id, type, and name/description
        """
        es = ElasticsearchService().client
        
        query = {"bool": {"must": []}}
        
        if exclude_id:
            query["bool"]["must_not"] = [{"term": {"id": exclude_id}}]
        
        if search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": search,
                    "fields": ["name^3", "description", "pattern", "x_ioc_value"]
                }
            })
        
        if not query["bool"]["must"]:
            query["bool"]["must"].append({"match_all": {}})
        
        try:
            result = es.search(
                index=cls.STIX_OBJECTS_INDEX,
                body={
                    "query": query,
                    "size": size,
                    "_source": ["id", "type", "name", "description", "pattern", "x_ioc_value"]
                }
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []
