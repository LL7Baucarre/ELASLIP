#!/usr/bin/env python3
"""
Script to create an admin user for IOC Manager.
Run this after starting Elasticsearch.
"""

import os
import sys
import uuid
import getpass
from datetime import datetime
from elasticsearch import Elasticsearch
import bcrypt


def create_admin_user(es, username, password, email=None):
    """Create an admin user in Elasticsearch."""
    
    # Check if user already exists
    result = es.search(
        index="users",
        body={
            "query": {
                "term": {"username": username}
            }
        }
    )
    
    if result["hits"]["total"]["value"] > 0:
        print(f"✗ User '{username}' already exists")
        return False
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Create user document
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "is_active": True,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    
    # Index user
    es.index(index="users", id=user_id, body=user)
    es.indices.refresh(index="users")
    
    print(f"✓ Created user: {username}")
    return True


def main():
    """Main entry point."""
    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    es_user = os.environ.get("ELASTICSEARCH_USER", "elastic")
    es_password = os.environ.get("ELASTICSEARCH_PASSWORD", "elastic123")
    
    print(f"\nIOC Manager - Create Admin User")
    print(f"=" * 50)
    print(f"Elasticsearch URL: {es_url}\n")
    
    # Construct URL with credentials if not already included
    if es_user and es_password and 'http://' in es_url and '@' not in es_url:
        es_url = es_url.replace('http://', f'http://{es_user}:{es_password}@')
    
    # Create Elasticsearch client
    es = Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False)
    
    # Check connection
    if not es.ping():
        print("✗ Cannot connect to Elasticsearch")
        print("  Make sure Elasticsearch is running")
        sys.exit(1)
    
    # Check if users index exists
    if not es.indices.exists(index="users"):
        print("✗ Users index does not exist")
        print("  Run init_elasticsearch.py first")
        sys.exit(1)
    
    # Get user input
    username = input("Username: ").strip()
    if not username:
        print("✗ Username is required")
        sys.exit(1)
    
    email = input("Email (optional): ").strip() or None
    
    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("✗ Password must be at least 8 characters")
        sys.exit(1)
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("✗ Passwords do not match")
        sys.exit(1)
    
    # Create user
    print()
    if create_admin_user(es, username, password, email):
        print(f"\n{'=' * 50}")
        print("✓ Admin user created successfully!")
        print(f"\nYou can now login at: http://localhost:5000/login")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
