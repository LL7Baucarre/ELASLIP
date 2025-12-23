"""Elasticsearch index mappings for IOC Manager."""


# IOC Index Mapping - STIX 2.1 Indicator format
IOC_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "pattern_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase"]
                }
            }
        }
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "type": {"type": "keyword"},
            "spec_version": {"type": "keyword"},
            "created": {"type": "date"},
            "modified": {"type": "date"},
            "name": {"type": "text"},
            "description": {"type": "text"},
            "pattern": {
                "type": "text",
                "analyzer": "pattern_analyzer",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "pattern_type": {"type": "keyword"},
            "pattern_version": {"type": "keyword"},
            "valid_from": {"type": "date"},
            "valid_until": {"type": "date"},
            "labels": {"type": "keyword"},
            "confidence": {"type": "keyword"},
            "threat_level": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "campaigns": {"type": "keyword"},
            "lang": {"type": "keyword"},
            "external_references": {
                "type": "nested",
                "properties": {
                    "source_name": {"type": "keyword"},
                    "url": {"type": "keyword"},
                    "external_id": {"type": "keyword"}
                }
            },
            "object_marking_refs": {"type": "keyword"},
            "granular_markings": {"type": "nested"},
            "indicator_types": {"type": "keyword"},
            "x_metadata": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "keyword"},
                    "ioc_value": {"type": "keyword"},
                    "pattern_hash": {"type": "keyword"},
                    "threat_level": {"type": "keyword"},
                    "tlp": {"type": "keyword"},
                    "campaigns": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "status": {"type": "keyword"},
                    "current_version": {"type": "integer"},
                    "created_by": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "keyword"},
                            "username": {"type": "keyword"}
                        }
                    },
                    "sources": {
                        "type": "nested",
                        "properties": {
                            "name": {"type": "keyword"},
                            "timestamp": {"type": "date"},
                            "metadata": {"type": "object", "enabled": False}
                        }
                    }
                }
            }
        }
    }
}


# Users Index Mapping
USERS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "username": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "email": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "password_hash": {"type": "keyword", "index": False},
            "is_admin": {"type": "boolean"},
            "role_id": {"type": "keyword"},
            "custom_permissions": {"type": "keyword"},
            "created_at": {"type": "date"},
            "last_login": {"type": "date"}
        }
    }
}


# API Keys Index Mapping
API_KEYS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "label": {"type": "text"},
            "key_hash": {"type": "keyword"},
            "key_prefix": {"type": "keyword"},
            "created_at": {"type": "date"},
            "last_used": {"type": "date"}
        }
    }
}


# API Configurations Index Mapping
API_CONFIGS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "description": {"type": "text"},
            "url": {"type": "keyword"},
            "method": {"type": "keyword"},
            "headers": {"type": "object", "enabled": False},
            "auth_type": {"type": "keyword"},
            "auth_token": {"type": "keyword", "index": False},
            "template": {"type": "object", "enabled": False},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "enabled": {"type": "boolean"}
        }
    }
}


# Webhooks Index Mapping
WEBHOOKS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "url": {"type": "keyword"},
            "events": {"type": "keyword"},
            "enabled": {"type": "boolean"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


# Webhook Logs Index Mapping
WEBHOOK_LOGS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "webhook_id": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "payload": {"type": "object", "enabled": False},
            "status_code": {"type": "integer"},
            "response_body": {"type": "text", "index": False},
            "success": {"type": "boolean"},
            "retry_count": {"type": "integer"},
            "error_message": {"type": "text"},
            "timestamp": {"type": "date"}
        }
    }
}


# Enrichment Cache Index Mapping
ENRICHMENT_CACHE_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "ioc_value": {"type": "keyword"},
            "api_config_id": {"type": "keyword"},
            "result": {"type": "object", "enabled": False},
            "cached_at": {"type": "date"},
            "expires_at": {"type": "date"}
        }
    }
}


# Import Jobs Index Mapping
IMPORT_JOBS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "filename": {"type": "keyword"},
            "file_type": {"type": "keyword"},
            "status": {"type": "keyword"},
            "progress": {"type": "integer"},
            "total_items": {"type": "integer"},
            "processed_items": {"type": "integer"},
            "added": {"type": "integer"},
            "updated": {"type": "integer"},
            "duplicates": {"type": "integer"},
            "errors": {"type": "integer"},
            "error_details": {"type": "object", "enabled": False},
            "started_at": {"type": "date"},
            "completed_at": {"type": "date"}
        }
    }
}


# Scan Results Index Mapping (WHOIS, Nmap)
SCAN_RESULTS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "tool": {"type": "keyword"},
            "target": {"type": "keyword"},
            "scan_type": {"type": "keyword"},
            "ports": {"type": "keyword"},
            "success": {"type": "boolean"},
            "result": {"type": "object", "enabled": False},
            "timestamp": {"type": "date"}
        }
    }
}


# IOC Relations Index Mapping
IOC_RELATIONS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "source_id": {"type": "keyword"},
            "target_id": {"type": "keyword"},
            "relation_type": {"type": "keyword"},
            "bidirectional": {"type": "boolean"},
            "created_by": {"type": "keyword"},
            "created_at": {"type": "date"}
        }
    }
}


# Audit Logs Index Mapping
AUDIT_LOGS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "user_id": {"type": "keyword"},
            "username": {"type": "keyword"},
            "action": {"type": "keyword"},
            "entity_type": {"type": "keyword"},
            "entity_id": {"type": "keyword"},
            "entity_name": {"type": "text"},
            "changes": {"type": "object", "enabled": False},
            "old_values": {"type": "object", "enabled": False},
            "new_values": {"type": "object", "enabled": False},
            "ip_address": {"type": "keyword"},
            "user_agent": {"type": "text", "index": False},
            "timestamp": {"type": "date"}
        }
    }
}


# IOC Versions Index Mapping
IOC_VERSIONS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "ioc_id": {"type": "keyword"},
            "version_number": {"type": "integer"},
            "snapshot": {"type": "object", "enabled": False},
            "changes": {"type": "object", "enabled": False},
            "modified_by": {"type": "keyword"},
            "modified_by_username": {"type": "keyword"},
            "modified_at": {"type": "date"},
            "created_at": {"type": "date"}
        }
    }
}


# Roles Index Mapping (RBAC)
ROLES_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"},
            "display_name": {"type": "text"},
            "description": {"type": "text"},
            "permissions": {"type": "keyword"},  # Array of permission strings
            "is_system": {"type": "boolean"},  # True for built-in roles
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


# Cases Index Mapping
CASES_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "description": {"type": "text"},
            "status": {"type": "keyword"},  # open, in-progress, closed, on-hold
            "priority": {"type": "keyword"},  # low, medium, high, critical
            "severity": {"type": "keyword"},  # informational, low, medium, high, critical
            "case_type": {"type": "keyword"},  # incident, investigation, threat-hunt, vulnerability
            "assignee_id": {"type": "keyword"},
            "assignee_name": {"type": "keyword"},
            "created_by_id": {"type": "keyword"},
            "created_by_name": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "tlp": {"type": "keyword"},
            "ioc_ids": {"type": "keyword"},  # Array of linked IOC IDs
            "incident_ids": {"type": "keyword"},  # Array of linked incident IDs
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "closed_at": {"type": "date"},
            "due_date": {"type": "date"}
        }
    }
}


# Incidents Index Mapping
INCIDENTS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "case_id": {"type": "keyword"},  # Parent case
            "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "description": {"type": "text"},
            "status": {"type": "keyword"},  # detected, analyzing, contained, eradicated, recovered, closed
            "severity": {"type": "keyword"},
            "category": {"type": "keyword"},  # malware, phishing, data-breach, ddos, unauthorized-access, etc.
            "ioc_ids": {"type": "keyword"},  # Array of linked IOC IDs
            "affected_assets": {"type": "text"},
            "attack_vector": {"type": "keyword"},
            "mitre_tactics": {"type": "keyword"},  # MITRE ATT&CK tactics
            "mitre_techniques": {"type": "keyword"},  # MITRE ATT&CK techniques
            "report_content": {"type": "text"},  # Markdown report content
            "report_sections": {"type": "object", "enabled": False},  # Structured report sections
            "created_by_id": {"type": "keyword"},
            "created_by_name": {"type": "keyword"},
            "assignee_id": {"type": "keyword"},
            "assignee_name": {"type": "keyword"},
            "detected_at": {"type": "date"},
            "contained_at": {"type": "date"},
            "resolved_at": {"type": "date"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


# Timeline Events Index Mapping
TIMELINE_EVENTS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "case_id": {"type": "keyword"},
            "incident_id": {"type": "keyword"},
            "event_type": {"type": "keyword"},  # detection, analysis, action, note, evidence, communication
            "title": {"type": "text"},
            "description": {"type": "text"},
            "content": {"type": "text"},  # Markdown content
            "attachments": {"type": "object", "enabled": False},
            "ioc_ids": {"type": "keyword"},
            "created_by_id": {"type": "keyword"},
            "created_by_name": {"type": "keyword"},
            "event_time": {"type": "date"},  # When the event actually occurred
            "created_at": {"type": "date"}
        }
    }
}


# Comments Index Mapping
COMMENTS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "entity_type": {"type": "keyword"},  # ioc, incident, case
            "entity_id": {"type": "keyword"},
            "parent_id": {"type": "keyword"},  # For threaded replies
            "content": {"type": "text"},
            "mentions": {"type": "keyword"},  # Array of mentioned user IDs
            "created_by_id": {"type": "keyword"},
            "created_by_name": {"type": "keyword"},
            "edited": {"type": "boolean"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


# Snippets Library Index Mapping
SNIPPETS_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "description": {"type": "text"},
            "content": {"type": "text"},  # Markdown content
            "category": {"type": "keyword"},  # executive-summary, technical-analysis, recommendations, ioc-table, etc.
            "tags": {"type": "keyword"},
            "is_global": {"type": "boolean"},  # Available to all users
            "created_by_id": {"type": "keyword"},
            "created_by_name": {"type": "keyword"},
            "usage_count": {"type": "integer"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"}
        }
    }
}


# All indices with their mappings
INDICES = {
    "ioc_manager_ioc": IOC_MAPPING,
    "ioc_manager_users": USERS_MAPPING,
    "ioc_manager_api_keys": API_KEYS_MAPPING,
    "ioc_manager_api_configs": API_CONFIGS_MAPPING,
    "ioc_manager_webhooks": WEBHOOKS_MAPPING,
    "ioc_manager_webhook_logs": WEBHOOK_LOGS_MAPPING,
    "ioc_manager_enrichment_cache": ENRICHMENT_CACHE_MAPPING,
    "ioc_manager_import_jobs": IMPORT_JOBS_MAPPING,
    "ioc_manager_scan_results": SCAN_RESULTS_MAPPING,
    "ioc_manager_ioc_relations": IOC_RELATIONS_MAPPING,
    "ioc_manager_audit_logs": AUDIT_LOGS_MAPPING,
    "ioc_manager_ioc_versions": IOC_VERSIONS_MAPPING,
    "ioc_manager_roles": ROLES_MAPPING,
    "ioc_manager_cases": CASES_MAPPING,
    "ioc_manager_incidents": INCIDENTS_MAPPING,
    "ioc_manager_timeline_events": TIMELINE_EVENTS_MAPPING,
    "ioc_manager_comments": COMMENTS_MAPPING,
    "ioc_manager_snippets": SNIPPETS_MAPPING
}
