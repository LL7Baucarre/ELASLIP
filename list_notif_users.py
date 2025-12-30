#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()

# Get all notifications
result = es.search('notifications', {
    'query': {'match_all': {}},
    'size': 100
})

# Extract unique user_ids
user_ids = set()
for hit in result['hits']['hits']:
    uid = hit['_source'].get('user_id')
    if uid:
        user_ids.add(uid)

print(f"\nUnique user_ids in notifications ({len(user_ids)}):")
for uid in sorted(user_ids):
    # Count how many notifications for this user
    count_result = es.search('notifications', {
        'query': {'term': {'user_id': uid}},
        'size': 0
    })
    count = count_result['hits']['total']['value']
    
    # Find username
    user_result = es.search('users', {'query': {'match': {'id': uid}}, 'size': 1})
    if user_result['hits']['hits']:
        username = user_result['hits']['hits'][0]['_source'].get('username', '?')
    else:
        username = '?'
    
    print(f"  - {uid[:20]}... ({username}): {count} notifications")
