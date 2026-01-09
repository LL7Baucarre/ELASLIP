#!/usr/bin/env python3
"""
Standalone script to initialize Elasticsearch indices.
Run this before starting the application for the first time.
"""

import os
import sys
import time
import logging
from elasticsearch import Elasticsearch

# Initialize logging for script
from app.logging_config import init_logging
init_logging()
logger = logging.getLogger(__name__)


# Index mappings
MAPPINGS = {
    "ioc": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "type": {"type": "keyword"},
                "spec_version": {"type": "keyword"},
                "created": {"type": "date"},
                "modified": {"type": "date"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "description": {"type": "text"},
                "pattern": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "pattern_type": {"type": "keyword"},
                "pattern_hash": {"type": "keyword"},
                "valid_from": {"type": "date"},
                "valid_until": {"type": "date"},
                "labels": {"type": "keyword"},
                "ioc_type": {"type": "keyword"},
                "ioc_value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "sources": {
                    "type": "nested",
                    "properties": {
                        "name": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "metadata": {"type": "object", "enabled": False}
                    }
                },
                "external_references": {
                    "type": "nested",
                    "properties": {
                        "source_name": {"type": "keyword"},
                        "url": {"type": "keyword"},
                        "external_id": {"type": "keyword"}
                    }
                }
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "users": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "username": {"type": "keyword"},
                "email": {"type": "keyword"},
                "password_hash": {"type": "keyword", "index": False},
                "is_active": {"type": "boolean"},
                "created_at": {"type": "date"},
                "last_login": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "api_keys": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "key_hash": {"type": "keyword", "index": False},
                "key_prefix": {"type": "keyword"},
                "is_active": {"type": "boolean"},
                "created_at": {"type": "date"},
                "last_used": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "api_configs": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "url_template": {"type": "keyword"},
                "method": {"type": "keyword"},
                "headers": {"type": "object", "enabled": False},
                "ioc_types": {"type": "keyword"},
                "response_template": {"type": "object", "enabled": False},
                "is_enabled": {"type": "boolean"},
                "timeout": {"type": "integer"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "webhooks": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "url": {"type": "keyword"},
                "secret": {"type": "keyword", "index": False},
                "events": {"type": "keyword"},
                "is_enabled": {"type": "boolean"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "webhook_logs": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "webhook_id": {"type": "keyword"},
                "webhook_name": {"type": "keyword"},
                "event": {"type": "keyword"},
                "payload": {"type": "object", "enabled": False},
                "status_code": {"type": "integer"},
                "response_body": {"type": "text", "index": False},
                "response_time": {"type": "integer"},
                "success": {"type": "boolean"},
                "error": {"type": "text"},
                "timestamp": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "enrichment_cache": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "api_config_id": {"type": "keyword"},
                "ioc_value": {"type": "keyword"},
                "ioc_type": {"type": "keyword"},
                "response": {"type": "object", "enabled": False},
                "transformed": {"type": "object", "enabled": False},
                "cached_at": {"type": "date"},
                "expires_at": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    },
    "import_jobs": {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "filename": {"type": "keyword"},
                "format": {"type": "keyword"},
                "status": {"type": "keyword"},
                "progress": {"type": "integer"},
                "stats": {
                    "type": "object",
                    "properties": {
                        "total": {"type": "integer"},
                        "imported": {"type": "integer"},
                        "duplicates": {"type": "integer"},
                        "errors": {"type": "integer"}
                    }
                },
                "error": {"type": "text"},
                "created_at": {"type": "date"},
                "completed_at": {"type": "date"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }
}


def wait_for_elasticsearch(es, max_retries=30, delay=2):
    """Wait for Elasticsearch to be ready."""
    for i in range(max_retries):
        try:
            if es.ping():
                logger.info("Elasticsearch is ready")
                return True
        except Exception:
            pass
        logger.info("Waiting for Elasticsearch... (%d/%d)", i+1, max_retries)
        time.sleep(delay)
    
    logger.error("Elasticsearch is not available")
    return False


def create_indices(es):
    """Create all indices if they don't exist."""
    for index_name, config in MAPPINGS.items():
        try:
            if not es.indices.exists(index=index_name):
                es.indices.create(index=index_name, body=config)
                logger.info("Creating index: %s", index_name)
            else:
                logger.info("Index already exists: %s", index_name)
        except Exception as e:
            logger.error("Failed to create index %s: %s", index_name, e)
            return False
    
    return True


def main():
    """Main entry point."""
    # Get Elasticsearch URL from environment or use default
    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    es_user = os.environ.get("ELASTICSEARCH_USER", "elastic")
    es_password = os.environ.get("ELASTICSEARCH_PASSWORD", "elastic123")
    
    logger.info("\nELASLIP - Elasticsearch Initialization")
    logger.info("%s", "=" * 50)
    logger.info("Elasticsearch URL: %s\n", es_url)
    
    # Construct URL with credentials if not already included
    if es_user and es_password and 'http://' in es_url and '@' not in es_url:
        es_url = es_url.replace('http://', f'http://{es_user}:{es_password}@')
    
    # Create Elasticsearch client
    es = Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False)
    
    # Wait for Elasticsearch
    if not wait_for_elasticsearch(es):
        sys.exit(1)
    
    # Get cluster info
    info = es.info()
    logger.info("  Cluster: %s", info.get('cluster_name', 'unknown'))
    logger.info("  Version: %s\n", info.get('version', {}).get('number', 'unknown'))
    
    # Create indices
    logger.info("Creating indices...")
    if not create_indices(es):
        sys.exit(1)
    
    logger.info("%s", "=" * 50)
    logger.info("Initialization complete!")
    logger.info("You can now start the application:")
    logger.info("  docker-compose up -d")
    logger.info("  or")
    logger.info("  flask run")


if __name__ == "__main__":
    main()
