#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from app.auth import User
from app.services.elasticsearch_service import ElasticsearchService

es = ElasticsearchService()

# Get admin user by ID
admin_id = '8c6976e5b5410415'
admin = User.get_by_id(admin_id)

print(f"\nAdmin User loaded by ID:")
print(f"  - username: {admin.username}")
print(f"  - id: {admin.id}")
print(f"  - ID is correct: {admin.id == admin_id}")
