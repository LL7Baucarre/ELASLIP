#!/usr/bin/env python3
"""
Check what username generated the last report
"""
import sys
sys.path.insert(0, '/app')
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()

# Get last report
result = es.search('app_config', {'query': {'term': {'type': 'report'}}, 'size': 1, 'sort': [{'created_at': {'order': 'desc'}}]})

if result['hits']['hits']:
    report = result['hits']['hits'][0]['_source']
    print(f"\nLast report:")
    print(f"  Task ID: {report.get('id')}")
    print(f"  Type: {report.get('type')}")
    print(f"  Created: {report.get('created_at')}")
    print(f"  Completed: {report.get('completed_at')}")
else:
    print("No reports found")

# Also check who the admin user is
admin_result = es.search('users', {'query': {'term': {'username.keyword': 'admin'}}, 'size': 1})
if admin_result['hits']['hits']:
    admin = admin_result['hits']['hits'][0]
    print(f"\nAdmin user:")
    print(f"  ID: {admin['_id']}")
    print(f"  Username: {admin['_source'].get('username')}")
