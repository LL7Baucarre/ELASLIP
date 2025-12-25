"""
Demo data generation script for ElasMISP.
Populates the database with random IOCs and relationships for demonstration purposes.
Only runs if DEMO_DATA_ENABLED=true is set in environment.
"""

import os
import sys
import random
import uuid
import secrets
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.ioc_service import IOCService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.case_service import CaseService, IncidentService, TimelineService
from app.services.comment_service import CommentService, SnippetService
from app.services.audit_service import AuditService
from app.auth import User, APIKey


# Check if demo data generation is enabled
def is_demo_enabled():
    """Check if demo data generation is enabled via environment variable."""
    return os.getenv('DEMO_DATA_ENABLED', 'false').lower() == 'true'


def generate_ipv4():
    """Generate a random IPv4 address."""
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))


def generate_domain():
    """Generate a random domain name."""
    domains = ['malware', 'phishing', 'botnet', 'c2', 'trojan', 'ransomware', 'exploit']
    tlds = ['com', 'net', 'org', 'ru', 'cn', 'io']
    name = random.choice(domains) + str(random.randint(100, 9999))
    tld = random.choice(tlds)
    return f"{name}.{tld}"


def generate_email():
    """Generate a random email address."""
    domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'test.com', 'spam.net']
    username = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
    return f"{username}@{random.choice(domains)}"


def generate_url():
    """Generate a random malicious URL."""
    domain = generate_domain()
    paths = ['admin', 'upload', 'shell', 'inject', 'payload', 'malware', 'c2', 'beacon']
    path = random.choice(paths)
    return f"http://{domain}/{path}/{random.randint(100, 9999)}"


def generate_hash(hash_type='md5'):
    """Generate a random hash."""
    if hash_type == 'md5':
        return ''.join(random.choices('0123456789abcdef', k=32))
    elif hash_type == 'sha1':
        return ''.join(random.choices('0123456789abcdef', k=40))
    elif hash_type == 'sha256':
        return ''.join(random.choices('0123456789abcdef', k=64))


def generate_asn():
    """Generate a random ASN."""
    return f"AS{random.randint(1000, 99999)}"


def generate_comment():
    """Generate a random comment."""
    comment_templates = [
        "This indicator has been seen in the wild. Recommend immediate containment.",
        "Confirmed malicious - multiple sources validate this threat.",
        "False positive - this is a legitimate service. Update status accordingly.",
        "High confidence assessment based on recent attacks patterns.",
        "Related to known APT group infrastructure. Cross-reference with other IOCs.",
        "Observed in network logs correlating with data exfiltration attempts.",
        "Legacy indicator - still relevant for historical analysis and context.",
        "Requires further investigation - check all related incidents.",
        "Low priority - assess against current threat landscape.",
        "Critical: This indicator is actively targeting our infrastructure.",
        "Intelligence suggests this campaign is still ongoing.",
        "Update severity level based on recent indicator activity.",
        "Correlates with multiple other incidents from the past month.",
        "Community feedback indicates reduced threat level.",
        "Recommend adding to enterprise-wide blocking rules."
    ]
    return random.choice(comment_templates)


def generate_timeline_event():
    """Generate a random timeline event description."""
    events = [
        "Status changed to active - indicator confirmed in network logs",
        "Threat level updated based on recent intelligence",
        "New relationship discovered with related IOC",
        "Incident escalation - added to critical threat watch list",
        "Cross-case correlation identified with similar attack pattern",
        "Analyst investigation initiated - preliminary findings inconclusive",
        "External intelligence feed update - confirmed additional activity",
        "Containment measures applied - indicator range blocked",
        "False positive assessment - indicator marked as benign",
        "Review scheduled with threat intelligence team",
        "Linked to active campaign - severity upgraded",
        "Network isolation implemented for affected assets",
        "Post-incident analysis complete - documented lessons learned",
        "Threat hunting expanded based on indicator cluster",
        "Intelligence shared with partner organizations"
    ]
    return random.choice(events)


def generate_snippet():
    """Generate a random code snippet."""
    snippet_templates = [
        {
            'title': 'YARA Rule - Malware Detection',
            'category': 'detection',
            'content': '''rule DetectMalware {
    meta:
        description = "Detects common malware patterns"
        author = "Demo Analyst"
    strings:
        $a = "malware_c2" nocase
        $b = {4D 5A 90 00}  // MZ header
    condition:
        any of them
}'''
        },
        {
            'title': 'STIX Pattern - Command & Control Detection',
            'category': 'detection',
            'content': '''[ipv4-addr:value = '192.168.1.1' OR domain-name:value = 'malicious.com'] AND
[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '10.0.0.1']'''
        },
        {
            'title': 'Incident Response Checklist',
            'category': 'procedures',
            'content': '''# Incident Response Steps

1. **Triage**: Validate the alert and determine severity
2. **Containment**: Isolate affected systems immediately
3. **Investigation**: Gather logs and forensic evidence
4. **Analysis**: Determine root cause and impact
5. **Eradication**: Remove all malicious artifacts
6. **Recovery**: Restore systems to safe state
7. **Lessons Learned**: Post-incident review'''
        },
        {
            'title': 'Phishing Email Analysis Template',
            'category': 'templates',
            'content': '''# Email Analysis Report

**From**: [sender email]
**Subject**: [email subject]
**Received**: [timestamp]

## Indicators
- SPF Check: [PASS/FAIL]
- DKIM Check: [PASS/FAIL]
- DMARC Check: [PASS/FAIL]
- Reply-To Analysis: [PASS/FAIL]

## Suspicious Elements
- URLs: [list URLs]
- Attachments: [list files]
- Embedded Objects: [descriptions]

## Verdict
[Safe / Suspicious / Malicious]'''
        },
        {
            'title': 'Threat Intelligence Report Template',
            'category': 'templates',
            'content': '''# Threat Intelligence Report

## Executive Summary
[High-level overview of threat]

## Technical Analysis
### Infrastructure
- IP Addresses: [list]
- Domains: [list]
- URLs: [list]

### Malware Capabilities
- Type: [ransomware/trojan/etc]
- C2 Protocol: [protocol used]
- Persistence Mechanism: [methods]

## Attribution
- Threat Actor: [APT group]
- Confidence: [High/Medium/Low]
- Motivation: [financial/espionage/etc]

## Recommendations
1. [mitigation step]
2. [detection step]
3. [hunting step]'''
        }
    ]
    return random.choice(snippet_templates)


def generate_random_iocs(count=100):
    """Generate random IOCs of various types."""
    # Only use types supported by STIX pattern generation
    ioc_types = ['ipv4', 'domain', 'email', 'url', 'md5', 'sha1', 'sha256', 'asn']

    iocs = []
    
    for _ in range(count):
        ioc_type = random.choice(ioc_types)
        
        if ioc_type == 'ipv4':
            value = generate_ipv4()
        elif ioc_type == 'domain':
            value = generate_domain()
        elif ioc_type == 'email':
            value = generate_email()
        elif ioc_type == 'url':
            value = generate_url()
        elif ioc_type == 'md5':
            value = generate_hash('md5')
        elif ioc_type == 'sha1':
            value = generate_hash('sha1')
        elif ioc_type == 'sha256':
            value = generate_hash('sha256')
        elif ioc_type == 'asn':
            value = generate_asn()
        else:
            value = 'unknown'
        
        # Random metadata
        threat_levels = ['low', 'medium', 'high', 'critical']
        confidence_levels = ['low', 'medium', 'high']
        tlp_levels = ['white', 'green', 'amber', 'red']
        labels = [
            'malware', 'phishing', 'botnet', 'c2', 'trojan', 
            'ransomware', 'exploit', 'ddos', 'spam', 'suspicious'
        ]
        sources = ['MISP', 'AlienVault', 'VirusTotal', 'Abuse.ch', 'Phishtank']
        # Comprehensive list of realistic APT/Campaign names
        campaigns = [
            'APT1', 'APT28', 'APT29', 'APT30', 'APT32', 'APT33', 'APT34', 'APT35', 'APT37', 'APT39', 'APT40', 'APT41',
            'Lazarus', 'Carbanak', 'FIN7', 'FIN6', 'FIN4', 'FIN5',
            'Turla', 'Snake', 'Gamaredon', 'Emotet', 'Trickbot', 'Ryuk',
            'Conti', 'LockBit', 'DarkSide', 'Colonial Pipeline',
            'Wizard Spider', 'Evil Corp', 'FIN10', 'FIN11',
            'Operation Stealth', 'Operation Ghost', 'Campaign Mimic',
            'Indrik Spider', 'Scattered Spider',
            'Unknown', 'Unattributed', 'Generic Malware', 'Opportunistic'
        ]
        
        ioc = {
            'ioc_type': ioc_type,
            'ioc_value': value,
            'name': f'{ioc_type.upper()} - {value[:30]}',
            'description': f'Demo IOC for {ioc_type}: {value}',
            'threat_level': random.choice(threat_levels),
            'confidence': random.choice(confidence_levels),
            'tlp': random.choice(tlp_levels),
            'labels': random.sample(labels, random.randint(1, 3)),
            'sources': [{'name': random.choice(sources), 'reference': f'ref-{uuid.uuid4()}'}],
            'campaigns': random.sample(campaigns, random.randint(1, 3)),  # Changed from 0, 2 to 1, 3 to ensure at least 1 campaign
            'valid_from': (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
            'valid_until': (datetime.utcnow() + timedelta(days=random.randint(1, 365))).isoformat(),
            'status': random.choice(['active', 'inactive', 'false_positive']),
        }
        
        iocs.append(ioc)
    
    return iocs


def populate_demo_data():
    """Populate database with demo data."""
    print("=" * 60)
    print("ElasMISP Demo Data Generator")
    print("=" * 60)
    
    if not is_demo_enabled():
        print("\nDemo data generation is DISABLED.")
        print("To enable, set DEMO_DATA_ENABLED=true in your .env file")
        return
    
    print("\nGenerating demo data...")
    
    # Create app context
    app = create_app()
    
    with app.app_context():
        service = IOCService()
        
        # Generate and insert IOCs
        print("\n1. Generating 100 random IOCs with diverse types...")
        iocs = generate_random_iocs(100)
        
        created_ids = []
        for i, ioc in enumerate(iocs, 1):
            try:
                # Convert sources list to single source dict
                source = None
                if ioc.get('sources'):
                    source = ioc['sources'][0]  # Take first source
                
                ioc_doc, is_new = service.create(
                    ioc_type=ioc['ioc_type'],
                    value=ioc['ioc_value'],
                    name=ioc.get('name'),
                    description=ioc.get('description'),
                    threat_level=ioc.get('threat_level'),
                    confidence=ioc.get('confidence'),
                    tlp=ioc.get('tlp'),
                    labels=ioc.get('labels', []),
                    source=source,
                    campaigns=ioc.get('campaigns', []),
                    valid_from=ioc.get('valid_from'),
                    valid_until=ioc.get('valid_until')
                )
                created_ids.append(ioc_doc['id'])
                if i % 10 == 0:
                    print(f"   Created {i}/100 IOCs...")
            except Exception as e:
                print(f"   Error creating IOC {i}: {str(e)}")
        
        print(f"   ✓ Created {len(created_ids)} IOCs successfully")
        
        # Create cases and incidents with IOC links
        print("\n2. Creating cases with related incidents...")
        case_service = CaseService()
        incident_service = IncidentService()
        
        case_titles = [
            'APT Campaign - Eastern Europe',
            'Ransomware Investigation - Healthcare',
            'Phishing Campaign - Financial Sector',
            'Malware Analysis - Infrastructure',
            'Data Breach - Government'
        ]
        
        incident_categories = ['malware', 'phishing', 'data_breach', 'ransomware', 'ddos', 'exploit']
        severities = ['low', 'medium', 'high', 'critical']
        statuses_case = ['open', 'in_progress', 'closed']
        
        created_cases = []
        created_incidents = []
        
        # Create 5 cases
        for i, case_title in enumerate(case_titles):
            try:
                # Select 5-10 random IOCs for this case
                num_iocs = random.randint(5, min(10, len(created_ids)))
                case_iocs = random.sample(created_ids, num_iocs)
                
                case_data = {
                    'title': case_title,
                    'description': f'Investigation into {case_title.lower()}',
                    'status': random.choice(statuses_case),
                    'priority': random.choice(['low', 'medium', 'high', 'critical']),
                    'severity': random.choice(severities),
                    'case_type': random.choice(['investigation', 'threat_hunt', 'incident_response']),
                    'tags': [random.choice(['urgent', 'high-profile', 'ongoing', 'suspicious'])],
                    'tlp': random.choice(['white', 'green', 'amber', 'red']),
                    'ioc_ids': case_iocs
                }
                
                case = case_service.create_case(case_data, 'demo_user', 'Demo User')
                created_cases.append(case)
                print(f"   Created case: {case_title}")
                
                # Create 2-4 incidents for this case
                num_incidents = random.randint(2, 4)
                for j in range(num_incidents):
                    try:
                        # Each incident gets 3-6 random IOCs
                        num_iocs_incident = random.randint(3, min(6, len(created_ids)))
                        incident_iocs = random.sample(created_ids, num_iocs_incident)
                        
                        incident_data = {
                            'case_id': case['id'],
                            'title': f'Incident {j+1}: {random.choice(["Attack", "Detection", "Alert"])} in {case_title}',
                            'description': f'Security incident related to {case_title}',
                            'status': random.choice(['detected', 'acknowledged', 'contained', 'resolved']),
                            'severity': random.choice(severities),
                            'category': random.choice(incident_categories),
                            'ioc_ids': incident_iocs,
                            'affected_assets': f'Asset Group {chr(65+j)}',
                            'attack_vector': random.choice(['network', 'email', 'physical', 'supply_chain']),
                            'mitre_tactics': random.sample(['reconnaissance', 'initial-access', 'execution', 'persistence', 'privilege-escalation'], random.randint(1, 3)),
                            'mitre_techniques': ['T1234', 'T1567', 'T1890']
                        }
                        
                        incident = incident_service.create_incident(incident_data, 'demo_user', 'Demo User')
                        created_incidents.append(incident)
                        print(f"      Created incident: {incident_data['title']}")
                    except Exception as e:
                        print(f"      Warning: Failed to create incident {j+1}: {str(e)}")
            except Exception as e:
                print(f"   Warning: Failed to create case {i+1}: {str(e)}")
        
        print(f"   ✓ Created {len(created_cases)} cases with {len(created_incidents)} incidents")
        
        # Create case-to-incident relationships
        print("\n3. Creating relationships between cases and incidents...")
        created_relations = 0
        for case in created_cases:
            # Link 1-2 random incidents to this case
            num_links = random.randint(1, min(2, len(created_incidents)))
            if num_links > 0:
                for incident in random.sample(created_incidents, min(num_links, len(created_incidents))):
                    try:
                        case_service.link_incident(case['id'], incident['id'])
                        created_relations += 1
                    except Exception as e:
                        print(f"      Warning: Failed to link incident: {str(e)}")
        
        print(f"   ✓ Created {created_relations} case-incident relationships")
        
        # Create demo users with different roles
        print("\n4. Creating demo users with different roles...")
        created_users = []
        user_config = [
            ('analyst1', 'analyst1@demo.local', 'Security Analyst #1', 'analyst'),
            ('analyst2', 'analyst2@demo.local', 'Security Analyst #2', 'analyst'),
            ('threat_intel', 'threat_intel@demo.local', 'Threat Intelligence Officer', 'threat_intel'),
            ('responder', 'responder@demo.local', 'Incident Responder', 'incident_responder'),
            ('manager', 'manager@demo.local', 'Security Manager', 'manager'),
            ('viewer', 'viewer@demo.local', 'Read-Only Viewer', 'viewer'),
        ]
        
        for username, email, display_name, role in user_config:
            try:
                user, error = User.create(username, email, 'demo_password_123', is_admin=False, role=role)
                if user:
                    created_users.append(user)
                    print(f"   Created {role:20s} | {username}")
                else:
                    print(f"   User {username} already exists")
            except Exception as e:
                print(f"      Warning: Failed to create user {username}: {str(e)}")
        
        print(f"   ✓ Created {len(created_users)} users with granular roles")
        
        # Create API keys
        print("\n5. Creating API keys...")
        api_keys_created = 0
        users_for_api_keys = created_users if created_users else []
        for user in users_for_api_keys[:1]:  # Create API key for first user
            try:
                key, key_obj = APIKey.create(user.id, 'Demo API Key')
                api_keys_created += 1
                api_key_user_id = user.id
                print(f"   Created API key for user: {user.username}")
                # Don't print the actual key, just confirmation
            except Exception as e:
                print(f"      Warning: Failed to create API key: {str(e)}")
        
        # Use first user's ID for remaining resources, or admin ID if no users created
        resource_user_id = api_key_user_id if created_users else 'a0e04ea15f41c020'  # admin default ID
        
        print(f"   ✓ Created {api_keys_created} API keys")
        
        # Create external API configuration
        print("\n6. Creating external API configuration...")
        es = ElasticsearchService()
        external_api_created = 0
        
        try:
            external_api_id = secrets.token_hex(16)
            external_api_config = {
                'id': external_api_id,
                'user_id': resource_user_id,
                'name': 'VirusTotal API',
                'description': 'Integration with VirusTotal for file and URL analysis',
                'url': 'https://www.virustotal.com/api/v3/files/{value}',
                'method': 'GET',
                'headers': {
                    'x-apikey': 'demo_api_key_xyz123'
                },
                'auth_type': 'header',
                'auth_token': None,
                'ioc_types': ['md5', 'sha1', 'sha256', 'url'],
                'enabled': True,
                'timeout': 30,
                'template': {
                    'ioc_type': '$.data.type',
                    'value': '$.data.attributes.sha256',
                    'labels': '$.data.attributes.tags',
                    'threat_level': '$.data.attributes.last_analysis_stats.malicious'
                },
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            es.index('api_configs', external_api_id, external_api_config)
            external_api_created += 1
            print(f"   Created external API: {external_api_config['name']}")
        except Exception as e:
            print(f"      Warning: Failed to create external API: {str(e)}")
        
        print(f"   ✓ Created {external_api_created} external API configurations")
        
        # Create webhook
        print("\n7. Creating webhook...")
        webhooks_created = 0
        
        try:
            webhook_id = secrets.token_hex(16)
            webhook = {
                'id': webhook_id,
                'user_id': resource_user_id,
                'name': 'Demo Webhook - Slack Integration',
                'url': 'https://hooks.slack.com/services/demo/webhook/url',
                'events': ['ioc.created', 'ioc.updated'],
                'enabled': True,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            es.index('webhooks', webhook_id, webhook)
            webhooks_created += 1
            print(f"   Created webhook: {webhook['name']}")
        except Exception as e:
            print(f"      Warning: Failed to create webhook: {str(e)}")
        
        print(f"   ✓ Created {webhooks_created} webhooks")
        
        # Create snippets
        print("\n8. Creating snippets...")
        snippet_service = SnippetService()
        snippets_created = 0
        
        for i in range(5):
            try:
                snippet_data = generate_snippet()
                snippet = snippet_service.create_snippet(
                    data={
                        'title': snippet_data['title'],
                        'description': f'Demo snippet for {snippet_data["category"]}',
                        'content': snippet_data['content'],
                        'category': snippet_data['category'],
                        'tags': ['demo', 'documentation'],
                        'is_global': True
                    },
                    user_id='demo_user',
                    username='Demo Analyst'
                )
                snippets_created += 1
                if (i + 1) % 2 == 0:
                    print(f"   Created {i + 1}/5 snippets...")
            except Exception as e:
                print(f"      Warning: Failed to create snippet: {str(e)}")
        
        print(f"   ✓ Created {snippets_created} snippets")
        
        # Create random relationships between IOCs
        if len(created_ids) > 1:
            print("\n9. Creating random IOC relationships...")
            relation_types = [
                'communicates-with',
                'exploits',
                'targets',
                'indicates',
                'based-on',
                'attributed-to',
                'drops',
                'downloads'
            ]
            
            es = ElasticsearchService()
            created_relations = 0
            failed_relations = 0
            
            # Create random number of relationships between 10-50 per IOC
            num_relations = random.randint(20, 100)
            
            for attempt in range(num_relations):
                try:
                    source_id = random.choice(created_ids)
                    target_id = random.choice([id for id in created_ids if id != source_id])
                    relation_type = random.choice(relation_types)
                    
                    relation_doc = {
                        'source_id': source_id,
                        'target_id': target_id,
                        'relation_type': relation_type,
                        'created': datetime.utcnow().isoformat(),
                        'strength': random.randint(1, 10)
                    }
                    
                    # Generate unique ID for this relation
                    relation_id = str(uuid.uuid4())
                    
                    # Index the relation with proper arguments: (index, doc_id, document)
                    response = es.index('ioc_relations', relation_id, relation_doc)
                    
                    if response:
                        created_relations += 1
                    else:
                        failed_relations += 1
                        
                except Exception as e:
                    failed_relations += 1
                    print(f"      Warning: Failed to create relation {attempt + 1}: {str(e)}")
            
            print(f"   ✓ Created {created_relations} relationships (out of {num_relations} attempts)")
            if failed_relations > 0:
                print(f"   ⚠ Failed to create {failed_relations} relationships")
        
        # Add comments to IOCs
        print("\n10. Adding comments to IOCs...")
        comment_service = CommentService()
        ioc_comments_created = 0
        
        for ioc_id in random.sample(created_ids, min(20, len(created_ids))):
            try:
                # Add 1-3 random comments per IOC
                num_comments = random.randint(1, 3)
                for _ in range(num_comments):
                    comment_service.create_comment(
                        entity_type='ioc',
                        entity_id=ioc_id,
                        content=generate_comment(),
                        user_id='demo_user',
                        username='Demo Analyst'
                    )
                    ioc_comments_created += 1
            except Exception as e:
                print(f"      Warning: Failed to create IOC comment: {str(e)}")
        
        print(f"   ✓ Created {ioc_comments_created} comments on IOCs")
        
        # Add comments to cases
        print("\n11. Adding comments to cases...")
        case_comments_created = 0
        
        for case in created_cases:
            try:
                # Add 2-4 comments per case
                num_comments = random.randint(2, 4)
                for _ in range(num_comments):
                    comment_service.create_comment(
                        entity_type='case',
                        entity_id=case['id'],
                        content=generate_comment(),
                        user_id='demo_user',
                        username='Demo Analyst'
                    )
                    case_comments_created += 1
            except Exception as e:
                print(f"      Warning: Failed to create case comment: {str(e)}")
        
        print(f"   ✓ Created {case_comments_created} comments on cases")
        
        # Add comments to incidents
        print("\n12. Adding comments to incidents...")
        incident_comments_created = 0
        
        for incident in created_incidents:
            try:
                # Add 1-3 comments per incident
                num_comments = random.randint(1, 3)
                for _ in range(num_comments):
                    comment_service.create_comment(
                        entity_type='incident',
                        entity_id=incident['id'],
                        content=generate_comment(),
                        user_id='demo_user',
                        username='Demo Analyst'
                    )
                    incident_comments_created += 1
            except Exception as e:
                print(f"      Warning: Failed to create incident comment: {str(e)}")
        
        print(f"   ✓ Created {incident_comments_created} comments on incidents")
        
        # Create timeline events (audit log entries)
        print("\n13. Creating timeline events...")
        timeline_service = TimelineService()
        timeline_events_created = 0
        
        # Timeline events for cases
        for case in created_cases:
            try:
                num_events = random.randint(3, 6)
                
                for idx in range(num_events):
                    event_types = ['detection', 'analysis', 'action', 'note', 'evidence', 'communication']
                    timeline_service.add_event(
                        data={
                            'case_id': case['id'],
                            'event_type': random.choice(event_types),
                            'title': f'Event {idx + 1}: {generate_timeline_event()}',
                            'description': f'Timeline event in case: {case["title"]}',
                            'content': f'# Investigation Update\n\n{generate_timeline_event()}\n\nAnalyst: Demo Analyst\nTime: {datetime.utcnow().isoformat()}',
                            'event_time': (datetime.utcnow() - timedelta(days=random.randint(0, 30))).isoformat() + 'Z'
                        },
                        user_id='demo_user',
                        username='Demo Analyst'
                    )
                    timeline_events_created += 1
            except Exception as e:
                print(f"      Warning: Failed to create case timeline event: {str(e)}")
        
        # Timeline events for incidents
        for incident in created_incidents:
            try:
                num_events = random.randint(2, 5)
                
                for idx in range(num_events):
                    event_types = ['detection', 'analysis', 'action', 'note', 'evidence', 'communication']
                    timeline_service.add_event(
                        data={
                            'incident_id': incident['id'],
                            'event_type': random.choice(event_types),
                            'title': f'Event {idx + 1}: {generate_timeline_event()}',
                            'description': f'Timeline event in incident: {incident.get("title", "Incident")}',
                            'content': f'# Incident Timeline\n\n{generate_timeline_event()}\n\nAnalyst: Demo Analyst\nTime: {datetime.utcnow().isoformat()}',
                            'event_time': (datetime.utcnow() - timedelta(days=random.randint(0, 30))).isoformat() + 'Z'
                        },
                        user_id='demo_user',
                        username='Demo Analyst'
                    )
                    timeline_events_created += 1
            except Exception as e:
                print(f"      Warning: Failed to create incident timeline event: {str(e)}")
        
        print(f"   ✓ Created {timeline_events_created} timeline events")
        
        print("\n" + "=" * 60)
        print("Demo data population complete!")
        print(f"Total IOCs created: {len(created_ids)}")
        print(f"Total IOC comments: {ioc_comments_created}")
        print(f"Total cases created: {len(created_cases)}")
        print(f"Total case comments: {case_comments_created}")
        print(f"Total incidents created: {len(created_incidents)}")
        print(f"Total incident comments: {incident_comments_created}")
        print(f"Total timeline events: {timeline_events_created}")
        print(f"Total demo users created: {len(created_users)}")
        print(f"Total API keys created: {api_keys_created}")
        print(f"Total external API configs: {external_api_created}")
        print(f"Total webhooks created: {webhooks_created}")
        print(f"Total snippets created: {snippets_created}")
        print("=" * 60)


if __name__ == '__main__':
    populate_demo_data()
