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
            "optional": ["name", "description", "objects", "object_refs", "x_observation_source"]
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
            "optional": ["abstract", "explanation", "authors"]
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
    def _find_duplicate(cls, sdo_type: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return existing STIX object if it appears to be a duplicate based on well-known keys."""
        es = ElasticsearchService().client
        try:
            # Indicators: try pattern hash first, then x_ioc_type/value
            if sdo_type == "indicator":
                import hashlib
                if "pattern" in data and data["pattern"]:
                    pattern_hash = hashlib.sha256(data["pattern"].encode()).hexdigest()
                    q = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"x_pattern_hash": pattern_hash}},
                                    {"term": {"type": "indicator"}}
                                ]
                            }
                        }
                    }
                    res = es.search(index=cls.STIX_OBJECTS_INDEX, body=q, size=1)
                    hits = res.get("hits", {}).get("hits", [])
                    if hits:
                        return hits[0]["_source"]

                if "x_ioc_type" in data and "x_ioc_value" in data:
                    q = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"type": "indicator"}},
                                    {"term": {"x_ioc_type": data["x_ioc_type"]}},
                                    {"term": {"x_ioc_value.keyword": data["x_ioc_value"]}}
                                ]
                            }
                        }
                    }
                    res = es.search(index=cls.STIX_OBJECTS_INDEX, body=q, size=1)
                    hits = res.get("hits", {}).get("hits", [])
                    if hits:
                        return hits[0]["_source"]

            # Other SDOs: match by exact name (case-insensitive) when available
            if "name" in data and data["name"]:
                name_val = data["name"].strip()
                # Use case-insensitive matching for name deduplication
                q = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"type": sdo_type}},
                                {
                                    "match": {
                                        "name": {
                                            "query": name_val,
                                            "operator": "and"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
                res = es.search(index=cls.STIX_OBJECTS_INDEX, body=q, size=10)
                hits = res.get("hits", {}).get("hits", [])
                if hits:
                    # Find exact match (case-insensitive)
                    for hit in hits:
                        existing_name = hit["_source"].get("name", "").strip()
                        if existing_name.lower() == name_val.lower():
                            return hit["_source"]
        except Exception:
            # On any ES error, conservatively return None so we don't block creation
            return None

        return None

    @classmethod
    def create_sdo(cls, sdo_type: str, data: Dict[str, Any], 
                   user_id: Optional[str] = None, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new STIX Domain Object (or return/merge with an existing one to avoid duplicates)
        
        Args:
            sdo_type: The STIX object type (indicator, malware, threat-actor, etc.)
            data: The object data (name, description, type-specific fields)
            user_id: Optional user ID who created this object
            username: Optional username who created this object
            
        Returns:
            The created or existing STIX object
        """
        if sdo_type not in cls.SDO_TYPES:
            raise ValueError(f"Unsupported SDO type: {sdo_type}")
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Check for an existing duplicate first
        existing = cls._find_duplicate(sdo_type, data)
        if existing:
            # Merge some useful fields (labels, description, confidence) and update modified timestamp
            updates: Dict[str, Any] = {"modified": now}

            # Merge labels
            existing_labels = set(existing.get("labels", []))
            new_labels = set(data.get("labels", [])) if data.get("labels") else set()
            merged_labels = list(existing_labels.union(new_labels))
            if merged_labels and merged_labels != existing.get("labels", []):
                updates["labels"] = merged_labels

            # Prefer fuller description if provided
            if data.get("description") and data.get("description") != existing.get("description"):
                updates["description"] = data.get("description")

            # Prefer higher confidence if provided
            if data.get("confidence") and data.get("confidence") > existing.get("confidence", 0):
                updates["confidence"] = data.get("confidence")

            # Add pattern hash for indicators if missing
            if sdo_type == "indicator" and "pattern" in data and "x_pattern_hash" not in existing:
                import hashlib
                updates["x_pattern_hash"] = hashlib.sha256(data["pattern"].encode()).hexdigest()

            # Add ELASLIP metadata if missing
            if user_id and not existing.get("x_elaslip_created_by_user_id"):
                updates["x_elaslip_created_by_user_id"] = user_id
            if username and not existing.get("x_elaslip_created_by_username"):
                updates["x_elaslip_created_by_username"] = username

            # Apply the update
            try:
                updated = cls.update_sdo(existing["id"], updates, 
                                        user_id=user_id, username=username,
                                        source_type="user_duplicate")
                if updated:
                    return updated
                else:
                    return existing
            except Exception:
                return existing

        # No duplicate found — proceed to create a new object
        stix_id = f"{sdo_type}--{uuid.uuid4()}"
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
        
        # Track creation as a source
        if user_id or username:
            stix_object["x_elaslip_sources"] = [{
                "type": "user_creation",
                "user_id": user_id,
                "username": username,
                "created_at": now
            }]

        # For indicators, generate pattern hash for deduplication
        if sdo_type == "indicator" and "pattern" in data and data["pattern"]:
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
    def update_sdo(cls, stix_id: str, updates: Dict[str, Any], 
                   user_id: Optional[str] = None, username: Optional[str] = None,
                   source_type: str = "user_edit") -> Optional[Dict[str, Any]]:
        """Update a STIX object"""
        es = ElasticsearchService().client
        
        # Get current object
        current = cls.get_sdo(stix_id)
        if not current:
            return None
        
        # Update modified timestamp
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        updates["modified"] = now
        
        # Merge updates
        for key, value in updates.items():
            if value is not None:
                current[key] = value
        
        # Track user edits in sources if user info provided
        if user_id or username:
            sources = current.get("x_elaslip_sources", [])
            # Ensure it's a list
            if not isinstance(sources, list):
                sources = []
            
            source_entry = {
                "type": source_type,
                "user_id": user_id,
                "username": username,
                "modified_at": now
            }
            
            # For duplicate detection, use created_at instead of modified_at
            if source_type == "user_duplicate":
                source_entry["created_at"] = now
                del source_entry["modified_at"]
            
            sources.append(source_entry)
            current["x_elaslip_sources"] = sources
        
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
        Search STIX objects by query string with intelligent matching
        
        Prioritizes exact name matches, then partial matches.
        
        Args:
            query_string: Search string
            sdo_types: Optional list of object types to filter
            size: Maximum results
            
        Returns:
            List of matching objects sorted by relevance
        """
        es = ElasticsearchService().client
        
        # Build query that prioritizes exact matches for name
        query = {
            "bool": {
                "should": [
                    # Exact match on name (highest priority)
                    {
                        "match": {
                            "name": {
                                "query": query_string,
                                "operator": "and"
                            }
                        }
                    },
                    # Term match on name (exact phrase)
                    {
                        "term": {
                            "name.keyword": query_string
                        }
                    },
                    # Partial matches with lower priority
                    {
                        "multi_match": {
                            "query": query_string,
                            "fields": ["name^2", "description", "pattern", "x_ioc_value", "labels"],
                            "operator": "or"
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        }
        
        if sdo_types:
            query["bool"]["filter"] = [{"terms": {"type": sdo_types}}]
        
        try:
            result = es.search(
                index=cls.STIX_OBJECTS_INDEX,
                body={
                    "query": query, 
                    "size": size,
                    "sort": [
                        {"_score": {"order": "desc"}},
                        {"name.keyword": {"order": "asc"}}
                    ]
                }
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
    
    @classmethod
    def get_graph_data(cls, start_id: Optional[str] = None, depth: int = 1, 
                       max_nodes: int = 500) -> Dict[str, Any]:
        """
        Get graph data for visualization with relationship depth control
        
        Args:
            start_id: Optional starting STIX object ID. If None, returns all objects and relationships
            depth: Relationship depth level (1-5). Controls how many levels of relationships to fetch
            max_nodes: Maximum number of nodes to return
            
        Returns:
            Dictionary with nodes and edges for graph visualization
        """
        es = ElasticsearchService().client
        nodes = []
        edges = []
        visited_ids = set()
        
        try:
            if start_id:
                # Build graph starting from specific object with depth control
                nodes, edges = cls._build_relationship_graph(
                    start_id, depth, max_nodes, es
                )
            else:
                # Get all STIX objects and relationships
                try:
                    # Fetch all STIX objects
                    objects_result = es.search(
                        index=cls.STIX_OBJECTS_INDEX,
                        body={"query": {"match_all": {}}, "size": max_nodes}
                    )
                    
                    for hit in objects_result.get("hits", {}).get("hits", []):
                        obj = hit["_source"]
                        node_id = obj["id"]
                        visited_ids.add(node_id)
                        
                        nodes.append({
                            "data": {
                                "id": node_id,
                                "label": obj.get("name", node_id.split("--")[0]),
                                "type": obj.get("type"),
                                "entity_type": "stix"
                            }
                        })
                    
                    # Fetch all relationships
                    rels_result = es.search(
                        index=cls.STIX_RELATIONSHIPS_INDEX,
                        body={"query": {"match_all": {}}, "size": max_nodes * 2}
                    )
                    
                    for hit in rels_result.get("hits", {}).get("hits", []):
                        rel = hit["_source"]
                        edge_id = rel["id"]
                        source_id = rel["source_ref"]
                        target_id = rel["target_ref"]
                        
                        # Only add edge if both nodes exist
                        if source_id in visited_ids and target_id in visited_ids:
                            edges.append({
                                "data": {
                                    "id": edge_id,
                                    "source": source_id,
                                    "target": target_id,
                                    "label": rel.get("relationship_type", "related")
                                }
                            })
                except Exception as e:
                    current_app.logger.error(f"Error fetching graph data: {e}")
            
            return {
                "nodes": nodes,
                "edges": edges
            }
        except Exception as e:
            current_app.logger.error(f"Error building graph data: {e}")
            return {"nodes": [], "edges": []}
    
    @classmethod
    def _build_relationship_graph(cls, start_id: str, depth: int, max_nodes: int,
                                   es_client) -> Tuple[List[Dict], List[Dict]]:
        """
        Build a relationship graph starting from a specific STIX object with depth control
        
        Args:
            start_id: Starting STIX object ID
            depth: Maximum relationship depth (1-5)
            max_nodes: Maximum nodes to include
            es_client: Elasticsearch client
            
        Returns:
            Tuple of (nodes, edges)
        """
        nodes = []
        edges = []
        visited_ids = set()
        current_level = {start_id}
        next_level = set()
        
        # Limit depth to 1-5
        depth = max(1, min(5, depth))
        
        try:
            # Add starting node
            start_obj = cls.get_sdo(start_id)
            if start_obj:
                visited_ids.add(start_id)
                nodes.append({
                    "data": {
                        "id": start_id,
                        "label": start_obj.get("name", start_id.split("--")[0]),
                        "type": start_obj.get("type"),
                        "entity_type": "stix"
                    }
                })
            
            # BFS to build relationship graph up to specified depth
            for current_depth in range(depth):
                if len(visited_ids) >= max_nodes:
                    break
                
                next_level = set()
                
                for obj_id in current_level:
                    # Get relationships for this object
                    relationships = cls.get_relationships(obj_id, "both")
                    
                    for rel in relationships:
                        rel_id = rel["id"]
                        source_id = rel["source_ref"]
                        target_id = rel["target_ref"]
                        rel_type = rel.get("relationship_type", "related")
                        
                        # Add edge
                        edges.append({
                            "data": {
                                "id": rel_id,
                                "source": source_id,
                                "target": target_id,
                                "label": rel_type
                            }
                        })
                        
                        # Track nodes to fetch in next level
                        if source_id not in visited_ids and len(visited_ids) < max_nodes:
                            next_level.add(source_id)
                        if target_id not in visited_ids and len(visited_ids) < max_nodes:
                            next_level.add(target_id)
                
                # Fetch and add next level nodes
                for node_id in next_level:
                    if len(visited_ids) >= max_nodes:
                        break
                    
                    if node_id not in visited_ids:
                        node_obj = cls.get_sdo(node_id)
                        if node_obj:
                            visited_ids.add(node_id)
                            nodes.append({
                                "data": {
                                    "id": node_id,
                                    "label": node_obj.get("name", node_id.split("--")[0]),
                                    "type": node_obj.get("type"),
                                    "entity_type": "stix"
                                }
                            })
                
                current_level = next_level
            
            return nodes, edges
        except Exception as e:
            current_app.logger.error(f"Error building relationship graph: {e}")
            return nodes, edges

    # ============================================================
    # STIX 2.1 ENRICHMENT SUPPORT
    # ============================================================
    
    @classmethod
    def extract_value_from_pattern(cls, pattern: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract IOC type and value from a STIX 2.1 pattern.
        
        Args:
            pattern: STIX pattern string, e.g. "[ipv4-addr:value = '8.8.8.8']"
        
        Returns:
            Tuple of (ioc_type, value) or (None, None) if not extractable
        """
        import re
        
        pattern_extractors = {
            'ipv4': re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
            'ipv6': re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]"),
            'domain': re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
            'url': re.compile(r"\[url:value\s*=\s*'([^']+)'\]"),
            'email': re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]"),
            'md5': re.compile(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]"),
            'sha1': re.compile(r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]"),
            'sha256': re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]"),
            'asn': re.compile(r"\[autonomous-system:(?:number|value)\s*=\s*'?(AS?\d+)'?\]"),
            'file': re.compile(r"\[file:name\s*=\s*'([^']+)'\]"),
            'registry': re.compile(r"\[windows-registry-key:key\s*=\s*'([^']+)'\]"),
            'mutex': re.compile(r"\[mutex:name\s*=\s*'([^']+)'\]"),
        }
        
        for ioc_type, regex in pattern_extractors.items():
            match = regex.search(pattern)
            if match:
                return ioc_type, match.group(1)
        
        return None, None
    
    @classmethod
    def enrich_sdo(cls, stix_id: str, enrichment_results: List[Dict[str, Any]], 
                   user_id: Optional[str] = None, 
                   username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Store enrichment results in a STIX object's x_elaslip_enrichment extension.
        
        STIX 2.1 allows custom properties with x_ prefix for extensions.
        We store enrichment data in x_elaslip_enrichment to maintain compliance.
        
        Args:
            stix_id: The STIX object ID to enrich
            enrichment_results: List of enrichment results from EnrichmentService
            user_id: User who triggered the enrichment
            username: Username who triggered the enrichment
        
        Returns:
            Updated STIX object or None if not found
        """
        current = cls.get_sdo(stix_id)
        if not current:
            return None
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Get or initialize x_elaslip_enrichment
        x_enrichment = current.get("x_elaslip_enrichment", {})
        if not isinstance(x_enrichment, dict):
            x_enrichment = {}
        
        # Ensure api_results array exists
        if "api_results" not in x_enrichment:
            x_enrichment["api_results"] = []
        
        # Process each enrichment result
        for result in enrichment_results:
            if not result.get("success"):
                continue
            
            api_result = {
                "api_name": result.get("api_name", "Unknown"),
                "api_id": result.get("api_id", ""),
                "enriched_at": now,
                "from_cache": result.get("from_cache", False),
            }
            
            # Add enrichment user info
            if user_id:
                api_result["enriched_by_user_id"] = user_id
            if username:
                api_result["enriched_by_username"] = username
            
            # Extract transformed data
            transformed = result.get("transformed", {})
            if transformed:
                # Map common enrichment fields to STIX-compatible extensions
                enrichment_fields = {}
                
                # Standard enrichment fields
                field_mappings = [
                    "threat_level", "confidence", "tlp", "risk_score", "severity",
                    "reputation", "malware_family", "country", "asn", "registrar",
                    "last_seen", "first_seen", "detection_ratio", "isp", "usage",
                    "labels", "name", "description"
                ]
                
                for field in field_mappings:
                    if field in transformed and transformed[field] is not None:
                        enrichment_fields[field] = transformed[field]
                
                # Add any extra/custom fields
                for key, value in transformed.items():
                    if key not in enrichment_fields and key not in ["ioc_type", "value", "__api_response__"]:
                        if value is not None:
                            enrichment_fields[key] = value
                
                api_result["data"] = enrichment_fields
            
            # Check if we already have a result from this API and update it
            existing_idx = None
            for idx, existing in enumerate(x_enrichment["api_results"]):
                if existing.get("api_id") == api_result["api_id"]:
                    existing_idx = idx
                    break
            
            if existing_idx is not None:
                x_enrichment["api_results"][existing_idx] = api_result
            else:
                x_enrichment["api_results"].append(api_result)
        
        # Update last enriched timestamp
        x_enrichment["last_enriched"] = now
        x_enrichment["enrichment_count"] = len(x_enrichment["api_results"])
        
        # Update the STIX object
        updates = {
            "x_elaslip_enrichment": x_enrichment,
            "modified": now
        }
        
        return cls.update_sdo(stix_id, updates, user_id=user_id, username=username)
    
    @classmethod
    def store_selected_enrichment(cls, stix_id: str, api_name: str, api_id: str,
                                   selected_fields: Dict[str, Any],
                                   user_id: Optional[str] = None,
                                   username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Store user-selected enrichment fields into a STIX object.
        
        This is for when a user reviews enrichment results and selects
        specific fields to store.
        
        Args:
            stix_id: The STIX object ID
            api_name: Name of the API that provided the data
            api_id: ID of the API configuration
            selected_fields: Dict of field names to values selected by user
            user_id: User who stored the enrichment
            username: Username who stored the enrichment
        
        Returns:
            Updated STIX object or None if not found
        """
        current = cls.get_sdo(stix_id)
        if not current:
            return None
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Get or initialize x_elaslip_enrichment
        x_enrichment = current.get("x_elaslip_enrichment", {})
        if not isinstance(x_enrichment, dict):
            x_enrichment = {}
        
        if "api_results" not in x_enrichment:
            x_enrichment["api_results"] = []
        
        # Create result object
        api_result = {
            "api_name": api_name,
            "api_id": api_id,
            "enriched_at": now,
            "data": selected_fields,
            "manually_selected": True
        }
        
        if user_id:
            api_result["enriched_by_user_id"] = user_id
        if username:
            api_result["enriched_by_username"] = username
        
        # Find existing or append
        existing_idx = None
        for idx, existing in enumerate(x_enrichment["api_results"]):
            if existing.get("api_id") == api_id:
                existing_idx = idx
                break
        
        if existing_idx is not None:
            x_enrichment["api_results"][existing_idx] = api_result
        else:
            x_enrichment["api_results"].append(api_result)
        
        x_enrichment["last_enriched"] = now
        x_enrichment["enrichment_count"] = len(x_enrichment["api_results"])
        
        # Update the STIX object
        updates = {
            "x_elaslip_enrichment": x_enrichment,
            "modified": now
        }
        
        return cls.update_sdo(stix_id, updates, user_id=user_id, username=username)
    
    @classmethod
    def get_enrichment(cls, stix_id: str) -> Optional[Dict[str, Any]]:
        """
        Get enrichment data for a STIX object.
        
        Returns:
            x_elaslip_enrichment dict or None
        """
        obj = cls.get_sdo(stix_id)
        if not obj:
            return None
        
        return obj.get("x_elaslip_enrichment")
