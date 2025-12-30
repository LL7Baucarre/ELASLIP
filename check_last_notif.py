#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()
result = es.search('notifications', {'query': {'match_all': {}}, 'size': 1, 'sort': [{'created_at': {'order': 'desc'}}]})

if result['hits']['hits']:
    n = result['hits']['hits'][0]['_source']
    print(f"\nLast notification:")
    print(f"  User: {n.get('user_id')}")
    print(f"  Type: {n.get('type')}")
    print(f"  Title: {n.get('title')}")
    print(f"  Created: {n.get('created_at')}")
else:
    print("No notifications found")
