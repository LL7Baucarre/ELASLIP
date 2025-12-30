#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()

# Get all unique user_ids in notifications
result = es.search('notifications', {
    'query': {'match_all': {}},
    'size': 100,
    'aggs': {
        'user_ids': {
            'terms': {
                'field': 'user_id',
                'size': 50
            }
        }
    }
})

print("\nAll unique user_ids in notifications:")
for bucket in result.get('aggregations', {}).get('user_ids', {}).get('buckets', []):
    user_id = bucket['key']
    count = bucket['doc_count']
    
    # Try to find who this user is
    user_result = es.search('users', {'query': {'match': {'id': user_id}}, 'size': 1})
    if user_result['hits']['hits']:
        username = user_result['hits']['hits'][0]['_source'].get('username', '?')
    else:
        username = '?'
    
    print(f"  - {user_id[:16]}... ({username}): {count} notifications")
