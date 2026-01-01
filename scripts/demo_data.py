"""
Demo data generation script for ELASLIP.
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
from app.services.checklist_template_service import ChecklistTemplateService
from app.services.checklist_service import ChecklistService
from app.services.audit_service import AuditService
from app.auth import User, APIKey

import logging
from app.logging_config import init_logging

# Initialize logging for script
init_logging()
logger = logging.getLogger(__name__)

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


def generate_checklist_templates():
    """Generate predefined checklist templates."""
    templates = [
        {
            'name': 'O365 Security Investigation',
            'description': 'Checklist for investigating suspicious activity in Microsoft Office 365 environment',
            'is_public': True,
            'tags': ['o365', 'cloud', 'investigation', 'incident-response'],
            'campaigns': [],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'Template for Microsoft 365 incident response. Suitable for account compromise and unauthorized access investigations.', 'user': 'admin', 'created_at': '2025-12-01T09:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Last updated: Dec 2025 with latest Azure AD and Teams security checks.', 'user': 'security_team', 'created_at': '2025-12-15T10:30:00Z'}
            ],
            'items': [
                {'title': 'Check Azure AD sign-in logs for suspicious access', 'description': 'Review sign-in activity for anomalies and risky sign-ins'},
                {'title': 'Review mailbox forwarding rules', 'description': 'Identify unauthorized mail forwarding to external domains'},
                {'title': 'Audit delegated access permissions', 'description': 'Check for unexpected mailbox delegates or send-as permissions'},
                {'title': 'Examine Teams channel permissions', 'description': 'Verify Teams channels and sharing settings'},
                {'title': 'Review MFA status for affected users', 'description': 'Ensure MFA is enabled and check recovery options'},
                {'title': 'Check OneDrive sharing settings', 'description': 'Identify external shares and unusual access patterns'},
                {'title': 'Review Exchange transport rules', 'description': 'Look for rules redirecting mail to external addresses'},
                {'title': 'Analyze mailbox rules and inboxes', 'description': 'Check for phishing and forwarding rules in affected mailboxes'},
                {'title': 'Collect audit logs', 'description': 'Export and analyze Office 365 audit logs for the investigation period'},
                {'title': 'Identify compromised accounts', 'description': 'List all accounts involved in the suspicious activity'},
                {'title': 'Reset credentials and enforce MFA', 'description': 'Reset passwords and enable MFA on all affected accounts'},
                {'title': 'Document findings and recommendations', 'description': 'Prepare incident report with remediation steps'}
            ]
        },
        {
            'name': 'Incident Response - Initial Triage',
            'description': 'Initial assessment and triage checklist for security incidents',
            'is_public': True,
            'tags': ['incident-response', 'triage', 'critical', 'soc'],
            'campaigns': [],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'MANDATORY template for all security incidents. Must be completed within 1 hour of detection.', 'user': 'incident_commander', 'created_at': '2025-11-01T08:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Updated to include modern SOC processes and automated alerting integration.', 'user': 'soc_lead', 'created_at': '2025-12-10T14:00:00Z'}
            ],
            'items': [
                {'title': 'Confirm the incident is real', 'description': 'Validate alert against false positives'},
                {'title': 'Determine incident severity level', 'description': 'Assess impact and urgency (critical/high/medium/low)'},
                {'title': 'Identify affected systems and users', 'description': 'List all impacted hosts, applications, and user accounts'},
                {'title': 'Collect initial evidence', 'description': 'Preserve logs, memory dumps, and suspicious files'},
                {'title': 'Isolate critical affected systems', 'description': 'Disconnect systems from network if necessary'},
                {'title': 'Notify incident response team', 'description': 'Escalate to appropriate teams based on severity'},
                {'title': 'Begin timeline of events', 'description': 'Document when the incident was first detected and initial observations'},
                {'title': 'Assign incident commander', 'description': 'Designate person responsible for coordination'},
                {'title': 'Open case in tracking system', 'description': 'Create case record and assign ticket number'},
                {'title': 'Setup secure communication channel', 'description': 'Establish isolated channel for incident team discussion'},
                {'title': 'Perform preliminary root cause analysis', 'description': 'Identify how the attacker gained initial access'},
                {'title': 'Create incident response plan', 'description': 'Document containment and remediation steps'}
            ]
        },
        {
            'name': 'Malware Analysis Workflow',
            'description': 'Checklist for analyzing potentially malicious files and artifacts',
            'is_public': True,
            'tags': ['malware-analysis', 'forensics', 'technical-analysis', 'detection'],
            'campaigns': [],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'Used by threat analysis team for technical malware investigations. Requires access to sandbox environment.', 'user': 'threat_analyst', 'created_at': '2025-10-15T11:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'IMPORTANT: Always execute samples in isolated sandbox. Never run on production systems.', 'user': 'security_lead', 'created_at': '2025-12-01T09:30:00Z'}
            ],
            'items': [
                {'title': 'Hash the suspicious file', 'description': 'Calculate MD5, SHA1, and SHA256 hashes'},
                {'title': 'Check VirusTotal and YARA databases', 'description': 'Search for file hashes in threat intelligence databases'},
                {'title': 'Examine file metadata', 'description': 'Check file properties, timestamps, and digital signatures'},
                {'title': 'Perform static analysis', 'description': 'Use IDA Pro or Ghidra to analyze binary structure'},
                {'title': 'Check strings for indicators', 'description': 'Extract and review ASCII/Unicode strings'},
                {'title': 'Analyze import tables', 'description': 'Review DLL imports and API calls'},
                {'title': 'Perform dynamic analysis in sandbox', 'description': 'Execute in isolated environment and monitor behavior'},
                {'title': 'Document network connections', 'description': 'Record C2 servers, DNS queries, and HTTP requests'},
                {'title': 'Identify registry modifications', 'description': 'Note registry keys and values the malware modifies'},
                {'title': 'Check for persistence mechanisms', 'description': 'Identify autorun, scheduled tasks, or service installation'},
                {'title': 'Correlate with known malware families', 'description': 'Link to known malware variants and campaigns'},
                {'title': 'Create YARA rules if unique', 'description': 'Develop detection signatures for future use'},
                {'title': 'Document findings in report', 'description': 'Compile analysis results and recommendations'}
            ]
        }
    ]
    return templates


def generate_checklists():
    """Generate demo checklists for testing."""
    import uuid
    
    checklists = [
        {
            'title': 'Q4 2025 Security Audit',
            'description': 'Quarterly security compliance and vulnerability assessment checklist',
            'tags': ['compliance', 'audit', 'security', 'Q4-2025'],
            'campaigns': [],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'This audit is mandatory for all departments. Results must be compiled by Dec 31.', 'user': 'security_team', 'created_at': '2025-12-20T08:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Escalate any critical findings immediately to CISO', 'user': 'manager', 'created_at': '2025-12-22T14:30:00Z'}
            ],
            'items': [
                {'id': str(uuid.uuid4()), 'title': 'Review firewall rules and access controls', 'description': 'Validate firewall policies are current', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': 'All inbound rules reviewed and validated', 'user': 'analyst1', 'created_at': '2025-12-26T10:30:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Audit user access and permissions', 'description': 'Verify least privilege principle is enforced', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': 'Found 3 users with excessive permissions, remediation in progress', 'user': 'analyst1', 'created_at': '2025-12-26T11:15:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Scan for vulnerabilities', 'description': 'Run vulnerability scans on all systems', 'completed': True, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Review patch management', 'description': 'Ensure all critical patches are applied', 'completed': False, 'comments': [{'id': str(uuid.uuid4()), 'text': 'Waiting for change approval window', 'user': 'analyst2', 'created_at': '2025-12-25T15:45:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Check SSL/TLS certificates', 'description': 'Verify expiration dates and cipher suites', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Test backup and recovery procedures', 'description': 'Validate disaster recovery capabilities', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Review security logs', 'description': 'Analyze logs for suspicious activity', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Conduct security training', 'description': 'Ensure all staff complete security awareness training', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Document findings', 'description': 'Create audit report with recommendations', 'completed': False, 'comments': []}
            ]
        },
        {
            'title': 'Active Incident - Phishing Campaign',
            'description': 'Ongoing investigation into targeted phishing campaign detected Dec 26',
            'tags': ['incident', 'phishing', 'active', 'threat-response'],
            'campaigns': ['APT28', 'Wizard Spider'],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'CRITICAL: This is an active incident. All items must be completed ASAP.', 'user': 'incident_commander', 'created_at': '2025-12-26T08:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Attribution confidence: MEDIUM. Indicators suggest APT28 or Wizard Spider involvement.', 'user': 'threat_intel', 'created_at': '2025-12-26T09:15:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Total impact: 47 users potentially affected. 5 confirmations of credential compromise.', 'user': 'responder1', 'created_at': '2025-12-26T10:00:00Z'}
            ],
            'items': [
                {'id': str(uuid.uuid4()), 'title': 'Identify all affected email accounts', 'description': 'Extract list of targeted users', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': '47 users identified as recipients', 'user': 'responder1', 'created_at': '2025-12-26T08:20:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Block malicious URLs at gateway', 'description': 'Add URLs to email filter blocklist', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': 'Blocked 12 URLs, 3 domains blacklisted', 'user': 'responder1', 'created_at': '2025-12-26T08:45:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Analyze phishing email headers', 'description': 'Extract sender IP and routing information', 'completed': True, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Check for credential theft indicators', 'description': 'Monitor for account compromise signs', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': '5 credential change events detected, accounts secured', 'user': 'responder2', 'created_at': '2025-12-26T12:00:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Send notification to affected users', 'description': 'Alert users to change passwords', 'completed': True, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Review email forwarding rules', 'description': 'Check for unauthorized mail forwarding', 'completed': False, 'comments': [{'id': str(uuid.uuid4()), 'text': 'Scan in progress, checking all user mailboxes', 'user': 'responder2', 'created_at': '2025-12-26T14:30:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Collect samples for analysis', 'description': 'Extract attachments and URLs for analysis', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Correlate with other incidents', 'description': 'Check for relationship with other campaigns', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Update threat intelligence', 'description': 'Share indicators with community', 'completed': False, 'comments': []}
            ]
        },
        {
            'title': 'Network Segmentation Review',
            'description': 'Review of network segmentation strategy and implementation',
            'tags': ['network', 'infrastructure', 'review', 'planning'],
            'campaigns': [],
            'comments': [
                {'id': str(uuid.uuid4()), 'text': 'Priority: HIGH. Network segmentation is critical for defense-in-depth.', 'user': 'architect', 'created_at': '2025-12-15T10:00:00Z'},
                {'id': str(uuid.uuid4()), 'text': 'Timeline: Complete initial review by end of Q1 2026. Full implementation Q2-Q3 2026.', 'user': 'project_manager', 'created_at': '2025-12-18T11:30:00Z'}
            ],
            'items': [
                {'id': str(uuid.uuid4()), 'title': 'Document network topology', 'description': 'Create updated network diagram', 'completed': True, 'comments': [{'id': str(uuid.uuid4()), 'text': 'Updated topology document stored in wiki', 'user': 'analyst3', 'created_at': '2025-12-24T09:00:00Z'}]},
                {'id': str(uuid.uuid4()), 'title': 'Identify critical assets', 'description': 'List systems requiring isolation', 'completed': True, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Review VLAN configuration', 'description': 'Validate VLAN segmentation', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Test cross-segment communication', 'description': 'Verify ACLs are properly enforced', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Document trust boundaries', 'description': 'Define trust levels between segments', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Review DMZ configuration', 'description': 'Validate externally-facing systems isolation', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Check data flow controls', 'description': 'Verify data exfiltration prevention', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Update network policies', 'description': 'Document approved communication rules', 'completed': False, 'comments': []},
                {'id': str(uuid.uuid4()), 'title': 'Plan segmentation improvements', 'description': 'Identify enhancement opportunities', 'completed': False, 'comments': []}
            ]
        }
    ]
    return checklists


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
    logger.info("%s", "=" * 60)
    logger.info("ELASLIP Demo Data Generator")
    logger.info("%s", "=" * 60)
    
    if not is_demo_enabled():
        logger.info("Demo data generation is DISABLED.")
        logger.info("To enable, set DEMO_DATA_ENABLED=true in your .env file")
        return
    
    logger.info("Generating demo data...")
    
    # Create app context
    app = create_app()
    
    with app.app_context():
        service = IOCService()
        
        # Generate and insert IOCs
        logger.info("1. Generating 100 random IOCs with diverse types...")
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
                    logger.info("Created %d/100 IOCs...", i)
            except Exception as e:
                logger.warning("Error creating IOC %d: %s", i, str(e))
        
        logger.info("Created %d IOCs successfully", len(created_ids))
        
        # Create cases and incidents with IOC links
        logger.info("2. Creating cases with related incidents...")
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
        statuses_case = ['open', 'in-progress', 'closed']
        
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
                logger.info("Created case: %s", case_title)
                
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
                            'status': random.choice(['detected', 'analyzing', 'contained', 'eradicated', 'recovered', 'closed']),
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
                        logger.info("Created incident: %s", incident_data['title'])
                    except Exception as e:
                        logger.warning("Failed to create incident %d: %s", j+1, str(e))
            except Exception as e:
                logger.warning("Failed to create case %d: %s", i+1, str(e))
        
        logger.info("Created %d cases with %d incidents", len(created_cases), len(created_incidents))
        
        # Create case-to-incident relationships
        logger.info("3. Creating relationships between cases and incidents...")
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
                        logger.warning("Failed to link incident: %s", str(e))
        
        logger.info("Created %d case-incident relationships", created_relations)
        
        # Create demo users with different roles
        logger.info("4. Creating demo users with different roles...")
        created_users = []
        user_config = [
            ('analyst1', 'analyst1@demo.local', 'Security Analyst #1', 'analyst'),
            ('analyst2', 'analyst2@demo.local', 'Security Analyst #2', 'analyst'),
            ('threat_intel', 'threat_intel@demo.local', 'Threat Intelligence Officer', 'threat_intel'),
            ('responder', 'responder@demo.local', 'Incident Responder', 'incident_responder'),

            ('viewer', 'viewer@demo.local', 'Read-Only Viewer', 'viewer'),
        ]
        
        for username, email, display_name, role in user_config:
            try:
                user, error = User.create(username, email, 'demo_password_123', is_admin=False, role=role)
                if user:
                    created_users.append(user)
                    logger.info("Created %s | %s", role, username)
                else:
                    logger.info("User %s already exists", username)
            except Exception as e:
                logger.warning("Failed to create user %s: %s", username, str(e))
        
        logger.info("Created %d users with granular roles", len(created_users))
        
        # Create API keys
        logger.info("5. Creating API keys...")
        api_keys_created = 0
        users_for_api_keys = created_users if created_users else []
        for user in users_for_api_keys[:1]:  # Create API key for first user
            try:
                key, key_obj = APIKey.create(user.id, 'Demo API Key')
                api_keys_created += 1
                api_key_user_id = user.id
                logger.info("Created API key for user: %s", user.username)
                # Don't print the actual key, just confirmation
            except Exception as e:
                logger.warning("Failed to create API key: %s", str(e))
        
        # Use first user's ID for remaining resources, or admin ID if no users created
        resource_user_id = api_key_user_id if created_users else 'a0e04ea15f41c020'  # admin default ID
        
        logger.info("Created %d API keys", api_keys_created)
        
        # Create external API configuration
        logger.info("6. Creating external API configuration...")
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
            logger.info("Created external API: %s", external_api_config['name'])
        except Exception as e:
            logger.warning("Failed to create external API: %s", str(e))
        
        logger.info("Created %d external API configurations", external_api_created)
        
        # Create webhook
        logger.info("7. Creating webhook...")
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
            logger.info("Created webhook: %s", webhook['name'])
        except Exception as e:
            logger.warning("Failed to create webhook: %s", str(e))
        
        logger.info("Created %d webhooks", webhooks_created)
        
        # Create snippets
        logger.info("8. Creating snippets...")
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
                    logger.info("Created %d/5 snippets...", i + 1)
            except Exception as e:
                logger.warning("Failed to create snippet: %s", str(e))
        
        logger.info("Created %d snippets", snippets_created)
        
        # Create checklist templates
        logger.info("9. Creating checklist templates...")
        template_service = ChecklistTemplateService()
        templates_created = 0
        
        try:
            templates_data = generate_checklist_templates()
            for template_data in templates_data:
                try:
                    template = template_service.create_template(
                        name=template_data['name'],
                        description=template_data['description'],
                        created_by='demo_user',
                        items=template_data['items'],
                        is_public=template_data['is_public'],
                        tags=template_data.get('tags', []),
                        campaigns=template_data.get('campaigns', []),
                        comments=template_data.get('comments', [])
                    )
                    templates_created += 1
                    logger.info("Created template: %s", template_data['name'])
                except Exception as e:
                    logger.warning("Failed to create template '%s': %s", template_data['name'], str(e))
        except Exception as e:
            logger.warning("Failed to generate templates: %s", str(e))
        
        logger.info("Created %d checklist templates", templates_created)
        
        # Create demo checklists
        logger.info("10. Creating demo checklists...")
        checklist_service = ChecklistService()
        checklists_created = 0
        
        try:
            checklists_data = generate_checklists()
            for checklist_data in checklists_data:
                try:
                    checklist = checklist_service.create_checklist(
                        title=checklist_data['title'],
                        description=checklist_data['description'],
                        created_by='demo_user',
                        items=checklist_data['items'],
                        tags=checklist_data.get('tags', []),
                        campaigns=checklist_data.get('campaigns', []),
                        comments=checklist_data.get('comments', [])
                    )
                    checklists_created += 1
                    logger.info("Created checklist: %s", checklist_data['title'])
                except Exception as e:
                    logger.warning("Failed to create checklist '%s': %s", checklist_data['title'], str(e))
        except Exception as e:
            logger.warning("Failed to generate checklists: %s", str(e))
        
        logger.info("Created %d checklists", checklists_created)
                # Create random relationships between IOCs
        if len(created_ids) > 1:
            logger.info("11. Creating random IOC relationships...")
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
                    logger.warning("Failed to create relation %d: %s", attempt + 1, str(e))
            
            logger.info("Created %d relationships (out of %d attempts)", created_relations, num_relations)
            if failed_relations > 0:
                logger.warning("Failed to create %d relationships", failed_relations)
        
        # Add comments to IOCs
        logger.info("Adding comments to IOCs...")
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
                logger.warning("Failed to create IOC comment: %s", str(e))
        
        logger.info("Created %d comments on IOCs", ioc_comments_created)
        
        # Add comments to cases
        logger.info("13. Adding comments to cases...")
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
                logger.warning("Failed to create case comment: %s", str(e))
        
        logger.info("Created %d comments on cases", case_comments_created)
        
        # Add comments to incidents
        logger.info("14. Adding comments to incidents...")
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
                logger.warning("Failed to create incident comment: %s", str(e))
        
        logger.info("Created %d comments on incidents", incident_comments_created)
        
        # Create timeline events (audit log entries)
        logger.info("15. Creating timeline events...")
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
                logger.warning("Failed to create case timeline event: %s", str(e))
        
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
                logger.warning("Failed to create incident timeline event: %s", str(e))
        
        logger.info("Created %d timeline events", timeline_events_created)
        logger.info("%s", "=" * 60)
        logger.info("Demo data population complete!")
        logger.info("Total IOCs created: %d", len(created_ids))
        logger.info("Total IOC comments: %d", ioc_comments_created)
        logger.info("Total cases created: %d", len(created_cases))
        logger.info("Total case comments: %d", case_comments_created)
        logger.info("Total incidents created: %d", len(created_incidents))
        logger.info("Total incident comments: %d", incident_comments_created)
        logger.info("Total timeline events: %d", timeline_events_created)
        logger.info("Total demo users created: %d", len(created_users))
        logger.info("Total API keys created: %d", api_keys_created)
        logger.info("Total external API configs: %d", external_api_created)
        logger.info("Total webhooks created: %d", webhooks_created)
        logger.info("Total snippets created: %d", snippets_created)
        logger.info("Total checklist templates created: %d", templates_created)
        logger.info("Total checklists created: %d", checklists_created)
        logger.info("%s", "=" * 60)


if __name__ == '__main__':
    populate_demo_data()
