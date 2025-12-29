#!/usr/bin/env python
"""Test STIX display in detail page."""

from app import create_app
from app.services.ioc_service import IOCService
import json

app = create_app()

with app.app_context():
    service = IOCService()
    
    # Get the first IOC
    result = service.list(page=1, per_page=1)
    if result['items']:
        ioc_id = result['items'][0]['id']
        print(f"\nTesting with IOC: {ioc_id}")
        
        # Get clean version - what template displays
        clean = service.get_stix_compliant(ioc_id)
        print("\n=== get_stix_compliant() - Displayed in detail.html ===")
        print(json.dumps(clean, indent=2)[:2000])
        
        print("\n\n=== Checking for ILLEGAL fields ===")
        illegal = ['campaigns', 'threat_level', 'tlp', 'status', 'risk_score', 'ioc_type', 'ioc_value', 'value']
        found_any = False
        for field in illegal:
            if field in clean:
                print(f"FOUND (BAD): {field}")
                found_any = True
        if not found_any:
            print("OK: No illegal fields")
        
        print("\n=== x_ fields present ===")
        for key in sorted(clean.keys()):
            if key.startswith('x_') and key != 'x_enrichment':
                print(f"OK: {key}")
        
        # Now test get() with aliases
        print("\n\n=== get() - Enriched version for templates ===")
        enriched = service.get(ioc_id)
        print("\nAlias fields present:")
        for field in ['threat_level', 'tlp', 'campaigns', 'value']:
            if field in enriched:
                val = enriched[field]
                if isinstance(val, (list, dict)):
                    val = str(val)[:50]
                print(f"  OK: {field} = {val}")
