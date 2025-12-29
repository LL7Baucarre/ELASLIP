#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import json

es = Elasticsearch(['http://elasticsearch:9200'], basic_auth=('elastic', 'elastic123'))

# Get one incident to see structure
result = es.search(index='elaslip_incidents', size=1)
if result['hits']['hits']:
    incident = result['hits']['hits'][0]['_source']
    print("Sample Incident:")
    print(json.dumps({k: v for k, v in incident.items() if k in ['name', 'status', 'severity', 'priority', 'category']}, indent=2))

# Get aggregations of incidents by status
try:
    agg_result = es.search(
        index='elaslip_incidents',
        aggs={'by_status': {'terms': {'field': 'status', 'size': 20}}}
    )
    print("\nIncidents by Status Aggregation:")
    if 'aggregations' in agg_result:
        for bucket in agg_result['aggregations']['by_status']['buckets']:
            print(f"  {bucket['key']}: {bucket['doc_count']}")
except Exception as e:
    print(f"Aggregation error: {e}")

# Check all incidents
result = es.search(index='elaslip_incidents', size=20, _source=['name', 'status', 'category'])
print("\nAll Incidents (first 20):")
for hit in result['hits']['hits']:
    src = hit['_source']
    print(f"  {src.get('name', 'N/A')} - status: {src.get('status', 'N/A')}, category: {src.get('category', 'N/A')}")

# Check all cases
print("\n" + "="*50)
result = es.search(index='elaslip_cases', size=10, _source=['name', 'status'])
print("All Cases (first 10):")
for hit in result['hits']['hits']:
    src = hit['_source']
    print(f"  {src.get('name', 'N/A')} - status: {src.get('status', 'N/A')}")

# Check cases aggregation
try:
    agg_result = es.search(
        index='elaslip_cases',
        aggs={'by_status': {'terms': {'field': 'status', 'size': 20}}}
    )
    print("\nCases by Status Aggregation:")
    if 'aggregations' in agg_result:
        for bucket in agg_result['aggregations']['by_status']['buckets']:
            print(f"  {bucket['key']}: {bucket['doc_count']}")
except Exception as e:
    print(f"Aggregation error: {e}")
