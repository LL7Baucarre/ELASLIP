#!/usr/bin/env python3
"""
Initialize OAuth infrastructure in Elasticsearch.

This script creates the oauth_accounts index if it doesn't exist.
Run this after upgrading to enable OAuth support.

Usage:
    python scripts/init_oauth.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.elasticsearch_service import ElasticsearchService
from app.elasticsearch.mappings import OAUTH_ACCOUNTS_MAPPING


def init_oauth_indices():
    """Initialize OAuth-related Elasticsearch indices."""
    app = create_app()
    
    with app.app_context():
        es = ElasticsearchService()
        index_name = 'oauth_accounts'
        full_index_name = es._get_index_name(index_name)
        
        print(f"Checking if {full_index_name} index exists...")
        
        # Check if index exists
        if es.es.indices.exists(index=full_index_name):
            print(f"✓ Index {full_index_name} already exists")
        else:
            print(f"Creating {full_index_name} index...")
            
            # Create index with mapping
            es.es.indices.create(
                index=full_index_name,
                body=OAUTH_ACCOUNTS_MAPPING
            )
            
            print(f"✓ Index {full_index_name} created successfully")
        
        print("\nOAuth infrastructure initialized!")
        print("\nNext steps:")
        print("1. Configure OAuth providers in .env (see .env.oauth.example)")
        print("2. Restart the application")
        print("3. Test OAuth login at /auth/login")


if __name__ == '__main__':
    print("=" * 60)
    print("OAuth Infrastructure Initialization")
    print("=" * 60)
    print()
    
    try:
        init_oauth_indices()
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        sys.exit(1)
