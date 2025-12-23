"""
Demo data generation script for ElasMISP.
Populates the database with random IOCs and relationships for demonstration purposes.
Only runs if DEMO_DATA_ENABLED=true is set in environment.
"""

import os
import sys
import random
import uuid
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.ioc_service import IOCService
from app.services.elasticsearch_service import ElasticsearchService


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
                
                result = service.create(
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
                created_ids.append(result[0]['id'])
                if i % 10 == 0:
                    print(f"   Created {i}/100 IOCs...")
            except Exception as e:
                print(f"   Error creating IOC {i}: {str(e)}")
        
        print(f"   ✓ Created {len(created_ids)} IOCs successfully")
        
        # Create random relationships between IOCs
        if len(created_ids) > 1:
            print("\n2. Creating random relationships...")
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
        
        print("\n" + "=" * 60)
        print("Demo data population complete!")
        print(f"Total IOCs created: {len(created_ids)}")
        print("=" * 60)


if __name__ == '__main__':
    populate_demo_data()
