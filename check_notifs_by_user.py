#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()

# Check notifications for admin user
admin_id = '8c6976e5b5410415'
result = es.search('notifications', {
    'query': {'match': {'user_id': admin_id}},
    'size': 10,
    'sort': [{'created_at': {'order': 'desc'}}]
})

print(f"\nNotifications for admin (8c6976e5b5410415):")
print(f"Total found: {len(result['hits']['hits'])}")

for hit in result['hits']['hits'][:5]:
    n = hit['_source']
    print(f"  - {n.get('title')} | {n.get('created_at')}")

# Also check the analyst1 user
analyst_id = '0854634a19571335'
result2 = es.search('notifications', {
    'query': {'match': {'user_id': analyst_id}},
    'size': 10,
    'sort': [{'created_at': {'order': 'desc'}}]
})

print(f"\nNotifications for analyst1 (0854634a19571335):")
print(f"Total found: {len(result2['hits']['hits'])}")

for hit in result2['hits']['hits'][:5]:
    n = hit['_source']
    print(f"  - {n.get('title')} | {n.get('created_at')}")
