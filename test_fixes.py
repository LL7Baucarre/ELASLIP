#!/usr/bin/env python3
"""Test dashboard and filters."""
import requests
import json

# Login
session = requests.Session()
resp = session.post('http://localhost:5000/login', data={'username': 'admin', 'password': 'admin123'})
print(f"Login status: {resp.status_code}")

# Test dashboard page
resp = session.get('http://localhost:5000/dashboard')
if 'in-progress' in resp.text:
    print("✓ Dashboard shows 'in-progress' status in template")
else:
    print("✗ Dashboard does NOT show 'in-progress' status")

# Test incidents list with category filter
resp = session.get('http://localhost:5000/api/incidents?category=malware')
data = resp.json()
print(f"\n✓ Incidents with category=malware filter:")
print(f"  Status: {resp.status_code}")
print(f"  Total: {data.get('total', 'N/A')}")
if data.get('items'):
    print(f"  First incident category: {data['items'][0].get('category', 'N/A')}")

# Test incidents list (general)
resp = session.get('http://localhost:5000/api/incidents')
data = resp.json()
print(f"\n✓ All incidents:")
print(f"  Status: {resp.status_code}")
print(f"  Total: {data.get('total', 'N/A')}")

# Check first incident has correct status
if data.get('items'):
    statuses = [inc.get('status') for inc in data['items'][:5]]
    print(f"  Sample incident statuses: {statuses}")
