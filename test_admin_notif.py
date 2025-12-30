#!/usr/bin/env python3
"""
Direct test: Load admin user and check their ID
"""
import sys
sys.path.insert(0, '/app')

from app.auth import User
from app.services.elasticsearch_service import ElasticsearchService
from app.services.notification_service import NotificationService

es = ElasticsearchService()
ns = NotificationService()

# Load admin by ID the way Flask-Login does it
admin_id = '8c6976e5b5410415'
admin_user = User.get_by_id(admin_id)

print(f"\n=== ADMIN USER LOADING TEST ===")
print(f"Loaded by ID: {admin_id}")
print(f"  - username: {admin_user.username}")
print(f"  - id attribute: {admin_user.id}")
print(f"  - id type: {type(admin_user.id)}")
print(f"  - id == '8c6976e5b5410415': {admin_user.id == '8c6976e5b5410415'}")

# Now create a notification for this user
print(f"\n=== CREATING TEST NOTIFICATION ===")
notif = ns.notify_report_completed(
    user_id=admin_user.id,
    report_type='test_direct',
    entity_name='Direct Test',
    task_id='test-direct-001'
)

print(f"Notification created:")
print(f"  - ID: {notif['id']}")
print(f"  - user_id stored: {notif['user_id']}")
print(f"  - user_id correct: {notif['user_id'] == admin_id}")

# Check if we can retrieve it
notifs = ns.get_user_notifications(admin_user.id, limit=5)
print(f"\nRetrieving notification for this user:")
print(f"  - Found: {len(notifs)} notifications")
if notifs:
    print(f"  - First: {notifs[0]['title']}")
