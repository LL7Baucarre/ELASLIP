#!/usr/bin/env python
"""Test STIX compliance of IOC creation and retrieval."""

from app import create_app
from app.services.ioc_service import IOCService

app = create_app()

with app.app_context():
    service = IOCService()
    
    # Create a test IOC
    ioc, is_new = service.create(
        ioc_type='sha256',
        value='e3b0c44298fc1c14e68b697dc3ef96d4f7d3d0e48451c4e20d91f92e7c40fb11',
        labels=['test', 'malware'],
        source={'name': 'test_source', 'timestamp': '2025-01-15T10:30:00Z'},
        threat_level='high',
        confidence='75',
        tlp='amber',
        campaigns=['test_campaign'],
        user_id='admin',
        username='admin'
    )
    
    print('\n=== Created IOC ===')
    print(f'ID: {ioc["id"]}')
    print(f'Is New: {is_new}')
    print(f'\n=== Fields in Created Document ===')
    for key in sorted(ioc.keys()):
        if not key.startswith('_'):
            val = ioc[key]
            if isinstance(val, (dict, list)) and len(str(val)) > 50:
                val = str(val)[:50] + '...'
            print(f'{key}: {val}')
    
    print(f'\n=== Checking for Illegal Duplicates ===')
    illegal_fields = ['campaigns', 'threat_level', 'tlp', 'status', 'risk_score', 
                     'ioc_type', 'ioc_value', 'pattern_hash', 'current_version', 'asn', 'country']
    found_illegal = False
    for field in illegal_fields:
        if field in ioc:
            print(f'❌ ILLEGAL: {field} found at root level!')
            found_illegal = True
    
    if not found_illegal:
        print('✅ No illegal fields found in created IOC')
    
    print(f'\n=== Getting IOC with get() (enriched) ===')
    enriched = service.get(ioc['id'])
    print('Aliases present:')
    alias_fields = ['threat_level', 'tlp', 'campaigns', 'status', 'risk_score', 'ioc_type', 'ioc_value', 'value']
    for key in sorted(enriched.keys()):
        if key in alias_fields:
            print(f'  ✅ {key}: {str(enriched[key])[:50]}')
    
    print(f'\n=== Getting IOC with get_stix_compliant() (clean) ===')
    clean = service.get_stix_compliant(ioc['id'])
    print('Fields in clean STIX version:')
    has_illegal = False
    for field in illegal_fields:
        if field in clean:
            print(f'  ❌ {field}: SHOULD NOT BE HERE')
            has_illegal = True
    
    if not has_illegal:
        print('  ✅ No illegal fields')
    
    print('\nCustom x_ fields present:')
    for key in sorted(clean.keys()):
        if key.startswith('x_') and key != 'x_enrichment':
            val = clean[key]
            if isinstance(val, (dict, list)):
                val = str(val)[:40] + '...'
            print(f'  ✅ {key}')
    
    # Print full clean JSON for inspection
    print('\n=== Full Clean STIX JSON (first 100 chars) ===')
    import json
    clean_json = json.dumps(clean, indent=2)
    print(clean_json[:500] + '...' if len(clean_json) > 500 else clean_json)
