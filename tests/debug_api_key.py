#!/usr/bin/env python3
"""Debug API key lookup."""

import sys
import hashlib
sys.path.insert(0, '/app')

from app.services.elasticsearch_service import ElasticsearchService

def debug_api_key():
    """Debug API key lookup."""
    
    es = ElasticsearchService()
    
    api_key = 'ioc_d32cc84774b646f59d449049548d66ac'
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    print(f"API Key: {api_key}")
    print(f"Key Hash: {key_hash}")
    
    # Search for the key
    result = es.search('api_keys', {
        'query': {'term': {'key_hash': key_hash}},
        'size': 10
    })
    
    print(f"\nSearch results: {result['hits']['total']['value']}")
    
    if result['hits']['total']['value'] > 0:
        for hit in result['hits']['hits']:
            print(f"\nFound key:")
            print(f"  ID: {hit['_id']}")
            print(f"  Data: {hit['_source']}")
    else:
        print("\nNo API key found! Listing all keys:")
        result = es.search('api_keys', {
            'query': {'match_all': {}},
            'size': 20
        })
        
        for hit in result['hits']['hits']:
            source = hit['_source']
            print(f"\n  - Key Hash: {source.get('key_hash', 'NO HASH')[:20]}...")
            print(f"    User ID: {source.get('user_id')}")
            print(f"    Active: {source.get('is_active')}")

if __name__ == "__main__":
    debug_api_key()
