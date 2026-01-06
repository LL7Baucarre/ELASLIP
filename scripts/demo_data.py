"""
Demo data generation script for ELASLIP.
Populates the database with STIX 2.1 Domain Objects and relationships for demonstration purposes.
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
from app.services.stix_service import STIXService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.case_service import CaseService, IncidentService, TimelineService
from app.services.comment_service import CommentService, SnippetService
from app.services.checklist_template_service import ChecklistTemplateService
from app.services.checklist_service import ChecklistService
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


def generate_coherent_threat_scenarios():
    """
    Generate coherent STIX 2.1 objects organized by realistic threat scenarios.
    Each scenario includes a complete attack chain with proper relationships.
    Returns: dict with 'objects' list and 'relationships' list for logical linking.
    """
    
    scenarios = {
        # ============================================================
        # SCENARIO 1: APT29 (Cozy Bear) - Espionnage gouvernemental
        # ============================================================
        'apt29_solarwinds': {
            'threat_actor': {
                'type': 'threat-actor',
                'name': 'APT29 (Cozy Bear)',
                'description': 'Russian state-sponsored threat actor known for sophisticated espionage campaigns targeting government, diplomatic, and policy organizations. Linked to Russian Foreign Intelligence Service (SVR).',
                'threat_actor_types': ['nation-state'],
                'sophistication': 'expert',
                'primary_motivation': 'organizational-gain',
                'secondary_motivations': ['ideology'],
                'resource_level': 'government',
                'aliases': ['Cozy Bear', 'The Dukes', 'YTTRIUM', 'Iron Hemlock', 'Grizzly Steppe'],
                'goals': ['Espionage', 'Intelligence gathering', 'Political influence'],
                'labels': ['apt', 'nation-state', 'russia'],
            },
            'intrusion_set': {
                'type': 'intrusion-set',
                'name': 'SolarWinds Supply Chain Compromise',
                'description': 'Sophisticated supply chain attack targeting SolarWinds Orion software to gain access to multiple government and enterprise networks.',
                'first_seen': '2020-03-01T00:00:00.000Z',
                'last_seen': '2021-06-30T00:00:00.000Z',
                'goals': ['Long-term access', 'Data exfiltration', 'Lateral movement'],
                'resource_level': 'government',
                'primary_motivation': 'organizational-gain',
                'labels': ['supply-chain', 'apt29'],
            },
            'campaign': {
                'type': 'campaign',
                'name': 'Operation SUNBURST',
                'description': 'Advanced persistent threat campaign leveraging compromised SolarWinds Orion updates to deploy SUNBURST backdoor across thousands of organizations.',
                'objective': 'Espionage and long-term persistent access to high-value government and corporate networks',
                'first_seen': '2020-03-01T00:00:00.000Z',
                'last_seen': '2021-01-15T00:00:00.000Z',
                'labels': ['campaign', 'supply-chain', 'sunburst'],
            },
            'malware': [
                {
                    'type': 'malware',
                    'name': 'SUNBURST',
                    'description': 'Sophisticated backdoor delivered via trojanized SolarWinds Orion updates. Features domain generation algorithm (DGA) for C2, anti-analysis techniques, and modular payload delivery.',
                    'is_family': True,
                    'malware_types': ['backdoor', 'trojan'],
                    'capabilities': ['anti-analysis', 'modular-payload', 'dga-c2'],
                    'labels': ['sunburst', 'backdoor', 'apt29'],
                },
                {
                    'type': 'malware',
                    'name': 'TEARDROP',
                    'description': 'Memory-only dropper used to deploy Cobalt Strike beacons. Loaded directly into memory to evade disk-based detection.',
                    'is_family': True,
                    'malware_types': ['dropper'],
                    'capabilities': ['memory-resident', 'cobalt-strike-loader'],
                    'labels': ['teardrop', 'dropper', 'apt29'],
                },
                {
                    'type': 'malware',
                    'name': 'RAINDROP',
                    'description': 'Loader malware similar to TEARDROP, used for deploying Cobalt Strike on specific high-value targets.',
                    'is_family': True,
                    'malware_types': ['loader', 'dropper'],
                    'labels': ['raindrop', 'loader', 'apt29'],
                },
            ],
            'tools': [
                {
                    'type': 'tool',
                    'name': 'Cobalt Strike',
                    'description': 'Commercial adversary simulation framework abused by APT29 for post-exploitation, lateral movement, and C2 communications.',
                    'tool_types': ['remote-access', 'command-and-control'],
                    'labels': ['cobalt-strike', 'c2', 'post-exploitation'],
                },
                {
                    'type': 'tool',
                    'name': 'AdFind',
                    'description': 'Active Directory reconnaissance tool used by APT29 to enumerate AD environments after initial access.',
                    'tool_types': ['information-gathering'],
                    'labels': ['adfind', 'reconnaissance', 'active-directory'],
                },
            ],
            'attack_patterns': [
                {
                    'type': 'attack-pattern',
                    'name': 'Supply Chain Compromise - T1195.002',
                    'description': 'Compromise of software supply chain to insert malicious code into legitimate software updates.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1195.002'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}],
                    'labels': ['supply-chain', 'initial-access'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'Domain Trust Discovery - T1482',
                    'description': 'Enumeration of domain trust relationships to identify paths for lateral movement.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1482'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'discovery'}],
                    'labels': ['discovery', 'active-directory'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'SAML Token Forging (Golden SAML) - T1606.002',
                    'description': 'Forging SAML tokens to access cloud resources without valid credentials.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1606.002'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'credential-access'}],
                    'labels': ['golden-saml', 'credential-access', 'cloud'],
                },
            ],
            'infrastructure': [
                {
                    'type': 'infrastructure',
                    'name': 'APT29 C2 Infrastructure - US East',
                    'description': 'Command and control servers hosted on US-based VPS providers, using legitimate cloud services for blending.',
                    'infrastructure_types': ['command-and-control'],
                    'labels': ['c2', 'apt29', 'us-based'],
                },
                {
                    'type': 'infrastructure',
                    'name': 'APT29 Staging Server - Europe',
                    'description': 'Staging infrastructure for payload delivery and data exfiltration, using European hosting providers.',
                    'infrastructure_types': ['staging', 'exfiltration'],
                    'labels': ['staging', 'apt29', 'europe'],
                },
            ],
            'indicators': [
                {
                    'type': 'indicator',
                    'name': 'SUNBURST C2 Domain',
                    'description': 'Command and control domain used by SUNBURST malware for beacon communications.',
                    'pattern': "[domain-name:value = 'avsvmcloud.com']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'domain',
                    'x_ioc_value': 'avsvmcloud.com',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['sunburst', 'c2', 'apt29'],
                    'confidence': 95,
                },
                {
                    'type': 'indicator',
                    'name': 'SUNBURST Malicious DLL Hash',
                    'description': 'SHA256 hash of trojanized SolarWinds.Orion.Core.BusinessLayer.dll containing SUNBURST backdoor.',
                    'pattern': "[file:hashes.'SHA-256' = 'd0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'sha256',
                    'x_ioc_value': 'd0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['sunburst', 'backdoor', 'apt29'],
                    'confidence': 100,
                },
                {
                    'type': 'indicator',
                    'name': 'APT29 C2 IP Address',
                    'description': 'IP address associated with APT29 command and control infrastructure.',
                    'pattern': "[ipv4-addr:value = '185.225.69.69']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'ipv4',
                    'x_ioc_value': '185.225.69.69',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['c2', 'apt29'],
                    'confidence': 85,
                },
                {
                    'type': 'indicator',
                    'name': 'TEARDROP Dropper Hash',
                    'description': 'SHA256 hash of TEARDROP memory-only dropper.',
                    'pattern': "[file:hashes.'SHA-256' = '118189f90da3788fe0f99c96f3f76ad2e1b8c6f4f3f9b7e8d3c4a5b6c7d8e9f0']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'sha256',
                    'x_ioc_value': '118189f90da3788fe0f99c96f3f76ad2e1b8c6f4f3f9b7e8d3c4a5b6c7d8e9f0',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['teardrop', 'dropper', 'apt29'],
                    'confidence': 90,
                },
            ],
            'vulnerabilities': [
                {
                    'type': 'vulnerability',
                    'name': 'SolarWinds Orion Supply Chain Compromise',
                    'description': 'Build process compromise allowing insertion of malicious code into SolarWinds Orion updates.',
                    'x_severity': 'critical',
                    'x_cvss_score': 10.0,
                    'x_affected_products': ['SolarWinds Orion Platform 2019.4 HF5', 'SolarWinds Orion Platform 2020.2', 'SolarWinds Orion Platform 2020.2.1'],
                    'labels': ['supply-chain', 'solarwinds'],
                },
            ],
            'identity': {
                'type': 'identity',
                'name': 'US Government Agencies',
                'description': 'Multiple US government agencies targeted by APT29 including Treasury, Commerce, and DHS.',
                'identity_class': 'organization',
                'sectors': ['government-national', 'defense'],
                'labels': ['victim', 'government'],
            },
            'course_of_action': {
                'type': 'course-of-action',
                'name': 'SUNBURST Mitigation',
                'description': 'Immediate isolation of affected SolarWinds servers, credential reset for all accounts with access, and enhanced monitoring for lateral movement indicators.',
                'x_recommended_remediation': 'Isolate SolarWinds servers, reset all credentials, deploy EDR, monitor for SAML token abuse',
                'labels': ['mitigation', 'sunburst'],
            },
        },
        
        # ============================================================
        # SCENARIO 2: LockBit 3.0 - Ransomware Healthcare
        # ============================================================
        'lockbit_healthcare': {
            'threat_actor': {
                'type': 'threat-actor',
                'name': 'LockBit Gang',
                'description': 'Prolific ransomware-as-a-service (RaaS) operation responsible for thousands of attacks globally. Known for aggressive extortion tactics and data leak site.',
                'threat_actor_types': ['crime-syndicate', 'criminal'],
                'sophistication': 'advanced',
                'primary_motivation': 'personal-gain',
                'resource_level': 'organization',
                'aliases': ['LockBit', 'ABCD Ransomware'],
                'goals': ['Financial extortion', 'Data theft', 'Ransomware deployment'],
                'labels': ['ransomware', 'raas', 'lockbit'],
            },
            'campaign': {
                'type': 'campaign',
                'name': 'LockBit Healthcare Campaign Q4 2025',
                'description': 'Targeted ransomware campaign against healthcare organizations exploiting vulnerable VPN appliances and RDP exposure.',
                'objective': 'Encrypt critical healthcare systems and extort ransom payments through double extortion (encryption + data leak threat)',
                'first_seen': '2025-10-01T00:00:00.000Z',
                'last_seen': '2025-12-31T00:00:00.000Z',
                'labels': ['campaign', 'ransomware', 'healthcare'],
            },
            'malware': [
                {
                    'type': 'malware',
                    'name': 'LockBit 3.0',
                    'description': 'Latest version of LockBit ransomware featuring improved encryption, anti-analysis, and the LockBit bug bounty program. Encrypts files with .lockbit extension.',
                    'is_family': True,
                    'malware_types': ['ransomware'],
                    'capabilities': ['encrypts-files', 'deletes-backups', 'spreads-via-network', 'anti-analysis'],
                    'labels': ['lockbit3', 'ransomware'],
                },
                {
                    'type': 'malware',
                    'name': 'StealBit',
                    'description': 'Data exfiltration tool used by LockBit affiliates to steal sensitive data before encryption for double extortion.',
                    'is_family': True,
                    'malware_types': ['spyware', 'trojan'],
                    'capabilities': ['data-exfiltration', 'credential-theft'],
                    'labels': ['stealbit', 'exfiltration', 'lockbit'],
                },
            ],
            'tools': [
                {
                    'type': 'tool',
                    'name': 'Mimikatz',
                    'description': 'Credential extraction tool used by LockBit affiliates for privilege escalation and lateral movement.',
                    'tool_types': ['credential-exploitation'],
                    'labels': ['mimikatz', 'credentials', 'lateral-movement'],
                },
                {
                    'type': 'tool',
                    'name': 'PsExec',
                    'description': 'Microsoft Sysinternals tool abused for remote execution and ransomware deployment across network.',
                    'tool_types': ['remote-access', 'execution'],
                    'labels': ['psexec', 'lateral-movement'],
                },
                {
                    'type': 'tool',
                    'name': 'Advanced IP Scanner',
                    'description': 'Network scanning tool used to identify targets for lateral movement.',
                    'tool_types': ['network-capture', 'information-gathering'],
                    'labels': ['scanner', 'reconnaissance'],
                },
            ],
            'attack_patterns': [
                {
                    'type': 'attack-pattern',
                    'name': 'Exploit Public-Facing Application - T1190',
                    'description': 'Exploitation of vulnerable VPN appliances (Fortinet, Citrix) for initial access.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1190'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}],
                    'labels': ['exploitation', 'vpn', 'initial-access'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'Data Encrypted for Impact - T1486',
                    'description': 'Encryption of data on target systems to interrupt availability and extort payment.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1486'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'impact'}],
                    'labels': ['encryption', 'ransomware', 'impact'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'Inhibit System Recovery - T1490',
                    'description': 'Deletion of volume shadow copies and backup catalogs to prevent recovery.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1490'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'impact'}],
                    'labels': ['backup-deletion', 'ransomware'],
                },
            ],
            'infrastructure': [
                {
                    'type': 'infrastructure',
                    'name': 'LockBit Data Leak Site',
                    'description': 'Tor-based data leak site where LockBit publishes stolen data from non-paying victims.',
                    'infrastructure_types': ['anonymization', 'exfiltration'],
                    'labels': ['tor', 'leak-site', 'lockbit'],
                },
                {
                    'type': 'infrastructure',
                    'name': 'LockBit Affiliate C2 Panel',
                    'description': 'Web-based panel used by LockBit affiliates to manage ransomware deployments and track payments.',
                    'infrastructure_types': ['command-and-control'],
                    'labels': ['c2', 'raas', 'lockbit'],
                },
            ],
            'indicators': [
                {
                    'type': 'indicator',
                    'name': 'LockBit 3.0 Ransomware Hash',
                    'description': 'SHA256 hash of LockBit 3.0 ransomware binary.',
                    'pattern': "[file:hashes.'SHA-256' = 'a56b41a6023f828cccaaef470874571d169fdb8f683a75eda018c6f5ad5797a3']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'sha256',
                    'x_ioc_value': 'a56b41a6023f828cccaaef470874571d169fdb8f683a75eda018c6f5ad5797a3',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['lockbit3', 'ransomware'],
                    'confidence': 100,
                },
                {
                    'type': 'indicator',
                    'name': 'LockBit Affiliate Initial Access IP',
                    'description': 'IP address used by LockBit affiliate for initial VPN exploitation attempts.',
                    'pattern': "[ipv4-addr:value = '91.243.44.142']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'ipv4',
                    'x_ioc_value': '91.243.44.142',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['lockbit', 'initial-access'],
                    'confidence': 80,
                },
                {
                    'type': 'indicator',
                    'name': 'StealBit Exfiltration Domain',
                    'description': 'Domain used by StealBit for data exfiltration before encryption.',
                    'pattern': "[domain-name:value = 'data-transfer-sec.xyz']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'domain',
                    'x_ioc_value': 'data-transfer-sec.xyz',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['stealbit', 'exfiltration'],
                    'confidence': 90,
                },
                {
                    'type': 'indicator',
                    'name': 'LockBit Ransom Note Filename',
                    'description': 'Standard ransom note filename dropped by LockBit 3.0.',
                    'pattern': "[file:name = 'LockBit_3.0_Ransomware_Note.txt']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'filename',
                    'x_ioc_value': 'LockBit_3.0_Ransomware_Note.txt',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['lockbit', 'ransom-note'],
                    'confidence': 95,
                },
            ],
            'vulnerabilities': [
                {
                    'type': 'vulnerability',
                    'name': 'CVE-2023-27997 - Fortinet SSL VPN RCE',
                    'description': 'Critical heap-based buffer overflow vulnerability in FortiOS SSL VPN allowing remote code execution.',
                    'x_severity': 'critical',
                    'x_cvss_score': 9.8,
                    'x_affected_products': ['FortiOS 7.2.x', 'FortiOS 7.0.x', 'FortiOS 6.4.x'],
                    'labels': ['fortinet', 'vpn', 'rce'],
                },
            ],
            'identity': {
                'type': 'identity',
                'name': 'Regional Healthcare Network',
                'description': 'Mid-sized healthcare organization with multiple hospitals and clinics targeted by LockBit.',
                'identity_class': 'organization',
                'sectors': ['healthcare'],
                'labels': ['victim', 'healthcare'],
            },
            'course_of_action': {
                'type': 'course-of-action',
                'name': 'LockBit Ransomware Response',
                'description': 'Immediate network isolation, backup verification, and incident response engagement. Do not pay ransom.',
                'x_recommended_remediation': 'Isolate affected systems, verify backup integrity, engage IR team, patch VPN vulnerabilities',
                'labels': ['mitigation', 'ransomware', 'lockbit'],
            },
        },
        
        # ============================================================
        # SCENARIO 3: FIN7 - Financial Sector Attacks
        # ============================================================
        'fin7_financial': {
            'threat_actor': {
                'type': 'threat-actor',
                'name': 'FIN7 (Carbanak Group)',
                'description': 'Sophisticated financially-motivated threat actor targeting retail, hospitality, and financial sectors. Known for point-of-sale malware and business email compromise.',
                'threat_actor_types': ['crime-syndicate'],
                'sophistication': 'advanced',
                'primary_motivation': 'personal-gain',
                'resource_level': 'organization',
                'aliases': ['Carbanak', 'Navigator Group', 'Anunak'],
                'goals': ['Financial theft', 'Credit card fraud', 'Wire fraud'],
                'labels': ['fin7', 'carbanak', 'financial-crime'],
            },
            'campaign': {
                'type': 'campaign',
                'name': 'FIN7 Banking Trojan Campaign 2025',
                'description': 'Targeted phishing campaign against financial institutions using malicious document attachments to deploy banking trojans.',
                'objective': 'Compromise financial institution networks to steal funds and customer financial data',
                'first_seen': '2025-09-01T00:00:00.000Z',
                'last_seen': '2025-12-31T00:00:00.000Z',
                'labels': ['campaign', 'banking-trojan', 'fin7'],
            },
            'malware': [
                {
                    'type': 'malware',
                    'name': 'Carbanak',
                    'description': 'Advanced banking trojan with capabilities for video recording, keylogging, and remote access. Used to steal millions from financial institutions.',
                    'is_family': True,
                    'malware_types': ['backdoor', 'trojan', 'spyware'],
                    'capabilities': ['keylogging', 'screen-capture', 'remote-access'],
                    'labels': ['carbanak', 'banking-trojan', 'fin7'],
                },
                {
                    'type': 'malware',
                    'name': 'GRIFFON',
                    'description': 'JavaScript-based backdoor used by FIN7 for initial reconnaissance and payload delivery.',
                    'is_family': True,
                    'malware_types': ['backdoor'],
                    'capabilities': ['javascript-based', 'reconnaissance'],
                    'labels': ['griffon', 'backdoor', 'fin7'],
                },
                {
                    'type': 'malware',
                    'name': 'BOOSTWRITE',
                    'description': 'Loader malware used by FIN7 to deploy additional payloads on compromised systems.',
                    'is_family': True,
                    'malware_types': ['loader', 'dropper'],
                    'labels': ['boostwrite', 'loader', 'fin7'],
                },
            ],
            'tools': [
                {
                    'type': 'tool',
                    'name': 'PowerShell Empire',
                    'description': 'Post-exploitation framework used by FIN7 for command execution and lateral movement.',
                    'tool_types': ['remote-access', 'command-and-control'],
                    'labels': ['empire', 'powershell', 'post-exploitation'],
                },
                {
                    'type': 'tool',
                    'name': 'SQLMap',
                    'description': 'SQL injection automation tool used for database exploitation.',
                    'tool_types': ['exploitation'],
                    'labels': ['sqlmap', 'sql-injection'],
                },
            ],
            'attack_patterns': [
                {
                    'type': 'attack-pattern',
                    'name': 'Spearphishing Attachment - T1566.001',
                    'description': 'Targeted phishing emails with malicious Office documents containing macros.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1566.001'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'initial-access'}],
                    'labels': ['phishing', 'initial-access'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'Command and Scripting Interpreter: PowerShell - T1059.001',
                    'description': 'Abuse of PowerShell for malware execution and persistence.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1059.001'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'}],
                    'labels': ['powershell', 'execution'],
                },
                {
                    'type': 'attack-pattern',
                    'name': 'Video Capture - T1125',
                    'description': 'Recording of victim screens to observe banking operations and procedures.',
                    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1125'}],
                    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'collection'}],
                    'labels': ['video-capture', 'collection'],
                },
            ],
            'infrastructure': [
                {
                    'type': 'infrastructure',
                    'name': 'FIN7 Phishing Infrastructure',
                    'description': 'Bulletproof hosting used for phishing campaigns and malware delivery.',
                    'infrastructure_types': ['hosting-malware', 'phishing'],
                    'labels': ['phishing', 'fin7'],
                },
                {
                    'type': 'infrastructure',
                    'name': 'FIN7 C2 Server Network',
                    'description': 'Distributed command and control infrastructure using compromised websites.',
                    'infrastructure_types': ['command-and-control'],
                    'labels': ['c2', 'fin7'],
                },
            ],
            'indicators': [
                {
                    'type': 'indicator',
                    'name': 'FIN7 Phishing Email Sender',
                    'description': 'Email address used in FIN7 spearphishing campaign targeting banks.',
                    'pattern': "[email-addr:value = 'compliance-update@secure-banking-docs.com']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'email',
                    'x_ioc_value': 'compliance-update@secure-banking-docs.com',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['phishing', 'fin7'],
                    'confidence': 85,
                },
                {
                    'type': 'indicator',
                    'name': 'Carbanak C2 Domain',
                    'description': 'Command and control domain used by Carbanak malware.',
                    'pattern': "[domain-name:value = 'cdn-update-service.net']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'domain',
                    'x_ioc_value': 'cdn-update-service.net',
                    'x_threat_level': 'critical',
                    'x_tlp': 'TLP:RED',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['carbanak', 'c2'],
                    'confidence': 90,
                },
                {
                    'type': 'indicator',
                    'name': 'GRIFFON Backdoor Hash',
                    'description': 'SHA256 hash of GRIFFON JavaScript backdoor.',
                    'pattern': "[file:hashes.'SHA-256' = 'b7e3f45a9c2d1e8f6a0b4c5d7e9f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'sha256',
                    'x_ioc_value': 'b7e3f45a9c2d1e8f6a0b4c5d7e9f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['griffon', 'fin7'],
                    'confidence': 88,
                },
                {
                    'type': 'indicator',
                    'name': 'FIN7 Malicious Document',
                    'description': 'Malicious Word document with macro used for initial access.',
                    'pattern': "[file:name MATCHES 'Invoice_[0-9]+\\.docm']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'filename',
                    'x_ioc_value': 'Invoice_*.docm',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['phishing', 'macro', 'fin7'],
                    'confidence': 75,
                },
                {
                    'type': 'indicator',
                    'name': 'FIN7 Exfiltration IP',
                    'description': 'IP address used for data exfiltration in FIN7 operations.',
                    'pattern': "[ipv4-addr:value = '45.142.213.17']",
                    'pattern_type': 'stix',
                    'x_ioc_type': 'ipv4',
                    'x_ioc_value': '45.142.213.17',
                    'x_threat_level': 'high',
                    'x_tlp': 'TLP:AMBER',
                    'indicator_types': ['malicious-activity'],
                    'labels': ['exfiltration', 'fin7'],
                    'confidence': 82,
                },
            ],
            'identity': {
                'type': 'identity',
                'name': 'Global Financial Institution',
                'description': 'Major international bank targeted by FIN7 for financial theft.',
                'identity_class': 'organization',
                'sectors': ['financial-services'],
                'labels': ['victim', 'banking'],
            },
            'course_of_action': {
                'type': 'course-of-action',
                'name': 'FIN7 Mitigation Strategies',
                'description': 'Email security hardening, macro execution policies, network segmentation for banking systems.',
                'x_recommended_remediation': 'Block macros in Office, implement email security gateway, segment SWIFT systems',
                'labels': ['mitigation', 'fin7', 'banking'],
            },
        },
    }
    
    return scenarios


def generate_coherent_cases_and_incidents(scenario_objects):
    """
    Generate cases and incidents that are coherent with the STIX scenarios.
    Links real STIX objects to cases/incidents for meaningful relationships.
    """
    cases_data = [
        {
            'title': 'APT29 SolarWinds Compromise Investigation',
            'description': 'Active investigation into potential compromise via trojanized SolarWinds Orion update. Multiple government agencies affected. CISA Emergency Directive 21-01 compliance required.',
            'status': 'in-progress',
            'priority': 'critical',
            'severity': 'critical',
            'case_type': 'incident_response',
            'tags': ['apt29', 'solarwinds', 'sunburst', 'supply-chain', 'nation-state'],
            'tlp': 'red',
            'scenario': 'apt29_solarwinds',
            'incidents': [
                {
                    'title': 'SUNBURST Backdoor Detection - DC01',
                    'description': 'SUNBURST backdoor detected on primary domain controller DC01. Indicators match known APT29 TTPs. Immediate isolation required.',
                    'status': 'containment',
                    'severity': 'critical',
                    'category': 'malware',
                    'affected_assets': 'DC01.corp.local, DC02.corp.local',
                    'attack_vector': 'supply_chain',
                    'mitre_tactics': ['initial-access', 'persistence', 'command-and-control'],
                    'mitre_techniques': ['T1195.002', 'T1546', 'T1071.001'],
                },
                {
                    'title': 'Lateral Movement Activity Detected',
                    'description': 'AdFind and BloodHound artifacts discovered indicating Active Directory reconnaissance. Multiple service accounts compromised.',
                    'status': 'investigating',
                    'severity': 'high',
                    'category': 'intrusion',
                    'affected_assets': 'Active Directory Forest',
                    'attack_vector': 'network',
                    'mitre_tactics': ['discovery', 'lateral-movement', 'credential-access'],
                    'mitre_techniques': ['T1482', 'T1021.002', 'T1003.001'],
                },
                {
                    'title': 'SAML Token Abuse Investigation',
                    'description': 'Evidence of Golden SAML attack targeting Azure AD and O365. Investigating unauthorized access to cloud resources.',
                    'status': 'investigating',
                    'severity': 'critical',
                    'category': 'data_breach',
                    'affected_assets': 'Azure AD, Microsoft 365, AWS',
                    'attack_vector': 'credential',
                    'mitre_tactics': ['credential-access', 'defense-evasion'],
                    'mitre_techniques': ['T1606.002', 'T1550.001'],
                },
            ],
        },
        {
            'title': 'LockBit 3.0 Ransomware - Healthcare Network',
            'description': 'Active ransomware incident affecting regional healthcare network. Patient data at risk. Business continuity severely impacted across 3 hospitals.',
            'status': 'in-progress',
            'priority': 'critical',
            'severity': 'critical',
            'case_type': 'incident_response',
            'tags': ['lockbit', 'ransomware', 'healthcare', 'hipaa', 'double-extortion'],
            'tlp': 'red',
            'scenario': 'lockbit_healthcare',
            'incidents': [
                {
                    'title': 'Initial VPN Exploitation',
                    'description': 'FortiGate VPN appliance exploited via CVE-2023-27997. Attacker gained initial foothold on perimeter network.',
                    'status': 'closed',
                    'severity': 'critical',
                    'category': 'exploit',
                    'affected_assets': 'FW-EDGE-01 (FortiGate 600E)',
                    'attack_vector': 'network',
                    'mitre_tactics': ['initial-access'],
                    'mitre_techniques': ['T1190'],
                },
                {
                    'title': 'LockBit Ransomware Deployment',
                    'description': 'LockBit 3.0 ransomware deployed across hospital network. 847 systems encrypted. Ransom demand: $5M in Bitcoin.',
                    'status': 'containment',
                    'severity': 'critical',
                    'category': 'ransomware',
                    'affected_assets': '847 Windows servers and workstations',
                    'attack_vector': 'network',
                    'mitre_tactics': ['impact', 'execution'],
                    'mitre_techniques': ['T1486', 'T1490', 'T1059.001'],
                },
                {
                    'title': 'Patient Data Exfiltration',
                    'description': 'StealBit tool detected exfiltrating patient records before encryption. Approximately 2.3M patient records potentially stolen.',
                    'status': 'investigating',
                    'severity': 'critical',
                    'category': 'data_breach',
                    'affected_assets': 'EMR Database, Patient Records Server',
                    'attack_vector': 'network',
                    'mitre_tactics': ['exfiltration', 'collection'],
                    'mitre_techniques': ['T1041', 'T1560.001'],
                },
                {
                    'title': 'Backup System Compromise',
                    'description': 'Veeam backup infrastructure targeted and encrypted. Offline backups being verified for recovery.',
                    'status': 'recovery',
                    'severity': 'high',
                    'category': 'ransomware',
                    'affected_assets': 'VEEAM-01, Backup Repository',
                    'attack_vector': 'network',
                    'mitre_tactics': ['impact'],
                    'mitre_techniques': ['T1490', 'T1485'],
                },
            ],
        },
        {
            'title': 'FIN7 Banking Trojan Investigation',
            'description': 'Investigation into targeted phishing campaign delivering Carbanak banking trojan to financial institution employees. Wire fraud attempt detected.',
            'status': 'in-progress',
            'priority': 'high',
            'severity': 'high',
            'case_type': 'investigation',
            'tags': ['fin7', 'carbanak', 'banking', 'phishing', 'wire-fraud'],
            'tlp': 'amber',
            'scenario': 'fin7_financial',
            'incidents': [
                {
                    'title': 'Spearphishing Campaign Detection',
                    'description': 'Targeted phishing emails detected targeting treasury department. Malicious macro-enabled documents attached.',
                    'status': 'closed',
                    'severity': 'high',
                    'category': 'phishing',
                    'affected_assets': '23 email accounts',
                    'attack_vector': 'email',
                    'mitre_tactics': ['initial-access'],
                    'mitre_techniques': ['T1566.001'],
                },
                {
                    'title': 'Carbanak Malware Infection',
                    'description': 'Carbanak banking trojan installed on 5 treasury workstations. Keylogging and screen capture capabilities active.',
                    'status': 'eradication',
                    'severity': 'critical',
                    'category': 'malware',
                    'affected_assets': 'TREAS-WS01 through TREAS-WS05',
                    'attack_vector': 'email',
                    'mitre_tactics': ['execution', 'collection', 'persistence'],
                    'mitre_techniques': ['T1059.001', 'T1056.001', 'T1125'],
                },
                {
                    'title': 'Wire Transfer Fraud Attempt',
                    'description': 'Attempted fraudulent wire transfer of $2.4M to offshore account. Transaction blocked by fraud detection system.',
                    'status': 'closed',
                    'severity': 'critical',
                    'category': 'fraud',
                    'affected_assets': 'SWIFT Terminal, Treasury Systems',
                    'attack_vector': 'insider',
                    'mitre_tactics': ['impact'],
                    'mitre_techniques': ['T1657'],
                },
            ],
        },
    ]
    
    return cases_data

def populate_demo_data():
    """Populate database with coherent demo data based on realistic threat scenarios."""
    print("=" * 60)
    print("ELASLIP Demo Data Generator - Coherent Threat Scenarios")
    print("=" * 60)
    
    if not is_demo_enabled():
        print("\nDemo data generation is DISABLED.")
        print("To enable, set DEMO_DATA_ENABLED=true in your .env file")
        return
    
    print("\nGenerating coherent demo data with realistic threat scenarios...")
    print("Scenarios: APT29 (SolarWinds), LockBit 3.0 (Healthcare), FIN7 (Financial)")
    
    # Create app context
    app = create_app()
    
    with app.app_context():
        # Get coherent threat scenarios
        scenarios = generate_coherent_threat_scenarios()
        
        # Track created objects by scenario for proper relationship building
        scenario_objects = {}  # {scenario_name: {object_type: [created_ids]}}
        all_created_ids = []
        
        print("\n" + "=" * 60)
        print("PHASE 1: Creating STIX Domain Objects by Scenario")
        print("=" * 60)
        
        for scenario_name, scenario_data in scenarios.items():
            print(f"\n--- Scenario: {scenario_name.upper()} ---")
            scenario_objects[scenario_name] = {}
            
            # Create Threat Actor
            if 'threat_actor' in scenario_data:
                try:
                    obj_data = scenario_data['threat_actor'].copy()
                    sdo_type = obj_data.pop('type')
                    stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                    scenario_objects[scenario_name]['threat_actor'] = stix_obj['id']
                    all_created_ids.append(stix_obj['id'])
                    print(f"   ✓ Threat Actor: {obj_data['name']}")
                except Exception as e:
                    print(f"   ✗ Threat Actor error: {e}")
            
            # Create Intrusion Set (if present)
            if 'intrusion_set' in scenario_data:
                try:
                    obj_data = scenario_data['intrusion_set'].copy()
                    sdo_type = obj_data.pop('type')
                    stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                    scenario_objects[scenario_name]['intrusion_set'] = stix_obj['id']
                    all_created_ids.append(stix_obj['id'])
                    print(f"   ✓ Intrusion Set: {obj_data['name']}")
                except Exception as e:
                    print(f"   ✗ Intrusion Set error: {e}")
            
            # Create Campaign
            if 'campaign' in scenario_data:
                try:
                    obj_data = scenario_data['campaign'].copy()
                    sdo_type = obj_data.pop('type')
                    stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                    scenario_objects[scenario_name]['campaign'] = stix_obj['id']
                    all_created_ids.append(stix_obj['id'])
                    print(f"   ✓ Campaign: {obj_data['name']}")
                except Exception as e:
                    print(f"   ✗ Campaign error: {e}")
            
            # Create Malware families
            if 'malware' in scenario_data:
                scenario_objects[scenario_name]['malware'] = []
                for malware_data in scenario_data['malware']:
                    try:
                        obj_data = malware_data.copy()
                        sdo_type = obj_data.pop('type')
                        stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                        scenario_objects[scenario_name]['malware'].append(stix_obj['id'])
                        all_created_ids.append(stix_obj['id'])
                        print(f"   ✓ Malware: {obj_data['name']}")
                    except Exception as e:
                        print(f"   ✗ Malware error: {e}")
            
            # Create Tools
            if 'tools' in scenario_data:
                scenario_objects[scenario_name]['tools'] = []
                for tool_data in scenario_data['tools']:
                    try:
                        obj_data = tool_data.copy()
                        sdo_type = obj_data.pop('type')
                        stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                        scenario_objects[scenario_name]['tools'].append(stix_obj['id'])
                        all_created_ids.append(stix_obj['id'])
                        print(f"   ✓ Tool: {obj_data['name']}")
                    except Exception as e:
                        print(f"   ✗ Tool error: {e}")
            
            # Create Attack Patterns
            if 'attack_patterns' in scenario_data:
                scenario_objects[scenario_name]['attack_patterns'] = []
                for ap_data in scenario_data['attack_patterns']:
                    try:
                        obj_data = ap_data.copy()
                        sdo_type = obj_data.pop('type')
                        stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                        scenario_objects[scenario_name]['attack_patterns'].append(stix_obj['id'])
                        all_created_ids.append(stix_obj['id'])
                        print(f"   ✓ Attack Pattern: {obj_data['name']}")
                    except Exception as e:
                        print(f"   ✗ Attack Pattern error: {e}")
            
            # Create Infrastructure
            if 'infrastructure' in scenario_data:
                scenario_objects[scenario_name]['infrastructure'] = []
                for infra_data in scenario_data['infrastructure']:
                    try:
                        obj_data = infra_data.copy()
                        sdo_type = obj_data.pop('type')
                        stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                        scenario_objects[scenario_name]['infrastructure'].append(stix_obj['id'])
                        all_created_ids.append(stix_obj['id'])
                        print(f"   ✓ Infrastructure: {obj_data['name']}")
                    except Exception as e:
                        print(f"   ✗ Infrastructure error: {e}")
            
            # Create Indicators (IOCs)
            if 'indicators' in scenario_data:
                scenario_objects[scenario_name]['indicators'] = []
                for ind_data in scenario_data['indicators']:
                    try:
                        obj_data = ind_data.copy()
                        sdo_type = obj_data.pop('type')
                        # Add valid_from/valid_until for indicators
                        obj_data['valid_from'] = (datetime.utcnow() - timedelta(days=90)).isoformat() + 'Z'
                        obj_data['valid_until'] = (datetime.utcnow() + timedelta(days=365)).isoformat() + 'Z'
                        stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                        scenario_objects[scenario_name]['indicators'].append(stix_obj['id'])
                        all_created_ids.append(stix_obj['id'])
                        print(f"   ✓ Indicator: {obj_data['name']}")
                    except Exception as e:
                        print(f"   ✗ Indicator error: {e}")
            
            # Create Vulnerabilities
            if 'vulnerabilities' in scenario_data:
                vuln_data = scenario_data['vulnerabilities']
                if isinstance(vuln_data, list):
                    scenario_objects[scenario_name]['vulnerabilities'] = []
                    for v in vuln_data:
                        try:
                            obj_data = v.copy()
                            sdo_type = obj_data.pop('type')
                            stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                            scenario_objects[scenario_name]['vulnerabilities'].append(stix_obj['id'])
                            all_created_ids.append(stix_obj['id'])
                            print(f"   ✓ Vulnerability: {obj_data['name']}")
                        except Exception as e:
                            print(f"   ✗ Vulnerability error: {e}")
            
            # Create Identity (victim)
            if 'identity' in scenario_data:
                try:
                    obj_data = scenario_data['identity'].copy()
                    sdo_type = obj_data.pop('type')
                    stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                    scenario_objects[scenario_name]['identity'] = stix_obj['id']
                    all_created_ids.append(stix_obj['id'])
                    print(f"   ✓ Identity: {obj_data['name']}")
                except Exception as e:
                    print(f"   ✗ Identity error: {e}")
            
            # Create Course of Action
            if 'course_of_action' in scenario_data:
                try:
                    obj_data = scenario_data['course_of_action'].copy()
                    sdo_type = obj_data.pop('type')
                    stix_obj = STIXService.create_sdo(sdo_type, obj_data, 'demo-user', 'demo')
                    scenario_objects[scenario_name]['course_of_action'] = stix_obj['id']
                    all_created_ids.append(stix_obj['id'])
                    print(f"   ✓ Course of Action: {obj_data['name']}")
                except Exception as e:
                    print(f"   ✗ Course of Action error: {e}")
        
        print(f"\n   Total STIX objects created: {len(all_created_ids)}")
        
        # ============================================================
        # PHASE 2: Create STIX Relationships (coherent attack chains)
        # ============================================================
        print("\n" + "=" * 60)
        print("PHASE 2: Creating Coherent STIX Relationships")
        print("=" * 60)
        
        relations_created = 0
        
        for scenario_name, objs in scenario_objects.items():
            print(f"\n--- Relationships for: {scenario_name.upper()} ---")
            
            # Threat Actor → Campaign (attributed-to)
            if 'threat_actor' in objs and 'campaign' in objs:
                try:
                    STIXService.create_relationship(
                        source_ref=objs['campaign'],
                        target_ref=objs['threat_actor'],
                        relationship_type='attributed-to',
                        user_id='demo-user', username='demo'
                    )
                    relations_created += 1
                    print(f"   ✓ Campaign → attributed-to → Threat Actor")
                except: pass
            
            # Threat Actor → Intrusion Set (attributed-to)
            if 'threat_actor' in objs and 'intrusion_set' in objs:
                try:
                    STIXService.create_relationship(
                        source_ref=objs['intrusion_set'],
                        target_ref=objs['threat_actor'],
                        relationship_type='attributed-to',
                        user_id='demo-user', username='demo'
                    )
                    relations_created += 1
                    print(f"   ✓ Intrusion Set → attributed-to → Threat Actor")
                except: pass
            
            # Campaign → Malware (uses)
            if 'campaign' in objs and 'malware' in objs:
                for malware_id in objs['malware']:
                    try:
                        STIXService.create_relationship(
                            source_ref=objs['campaign'],
                            target_ref=malware_id,
                            relationship_type='uses',
                            user_id='demo-user', username='demo'
                        )
                        relations_created += 1
                        print(f"   ✓ Campaign → uses → Malware")
                    except: pass
            
            # Campaign → Tools (uses)
            if 'campaign' in objs and 'tools' in objs:
                for tool_id in objs['tools']:
                    try:
                        STIXService.create_relationship(
                            source_ref=objs['campaign'],
                            target_ref=tool_id,
                            relationship_type='uses',
                            user_id='demo-user', username='demo'
                        )
                        relations_created += 1
                        print(f"   ✓ Campaign → uses → Tool")
                    except: pass
            
            # Campaign → Attack Patterns (uses)
            if 'campaign' in objs and 'attack_patterns' in objs:
                for ap_id in objs['attack_patterns']:
                    try:
                        STIXService.create_relationship(
                            source_ref=objs['campaign'],
                            target_ref=ap_id,
                            relationship_type='uses',
                            user_id='demo-user', username='demo'
                        )
                        relations_created += 1
                        print(f"   ✓ Campaign → uses → Attack Pattern")
                    except: pass
            
            # Malware → Infrastructure (uses/communicates-with)
            if 'malware' in objs and 'infrastructure' in objs:
                for malware_id in objs['malware']:
                    for infra_id in objs['infrastructure']:
                        try:
                            STIXService.create_relationship(
                                source_ref=malware_id,
                                target_ref=infra_id,
                                relationship_type='communicates-with',
                                user_id='demo-user', username='demo'
                            )
                            relations_created += 1
                            print(f"   ✓ Malware → communicates-with → Infrastructure")
                        except: pass
            
            # Indicators → Malware (indicates)
            if 'indicators' in objs and 'malware' in objs:
                for i, ind_id in enumerate(objs['indicators']):
                    if i < len(objs['malware']):
                        try:
                            STIXService.create_relationship(
                                source_ref=ind_id,
                                target_ref=objs['malware'][i % len(objs['malware'])],
                                relationship_type='indicates',
                                user_id='demo-user', username='demo'
                            )
                            relations_created += 1
                            print(f"   ✓ Indicator → indicates → Malware")
                        except: pass
            
            # Indicators → Infrastructure (indicates)
            if 'indicators' in objs and 'infrastructure' in objs:
                for i, ind_id in enumerate(objs['indicators']):
                    if objs['infrastructure']:
                        try:
                            STIXService.create_relationship(
                                source_ref=ind_id,
                                target_ref=objs['infrastructure'][i % len(objs['infrastructure'])],
                                relationship_type='indicates',
                                user_id='demo-user', username='demo'
                            )
                            relations_created += 1
                            print(f"   ✓ Indicator → indicates → Infrastructure")
                        except: pass
            
            # Campaign → Identity (targets)
            if 'campaign' in objs and 'identity' in objs:
                try:
                    STIXService.create_relationship(
                        source_ref=objs['campaign'],
                        target_ref=objs['identity'],
                        relationship_type='targets',
                        user_id='demo-user', username='demo'
                    )
                    relations_created += 1
                    print(f"   ✓ Campaign → targets → Identity (victim)")
                except: pass
            
            # Malware → Vulnerabilities (exploits)
            if 'malware' in objs and 'vulnerabilities' in objs:
                for malware_id in objs['malware']:
                    for vuln_id in objs['vulnerabilities']:
                        try:
                            STIXService.create_relationship(
                                source_ref=malware_id,
                                target_ref=vuln_id,
                                relationship_type='exploits',
                                user_id='demo-user', username='demo'
                            )
                            relations_created += 1
                            print(f"   ✓ Malware → exploits → Vulnerability")
                        except: pass
            
            # Course of Action → Malware (mitigates)
            if 'course_of_action' in objs and 'malware' in objs:
                for malware_id in objs['malware']:
                    try:
                        STIXService.create_relationship(
                            source_ref=objs['course_of_action'],
                            target_ref=malware_id,
                            relationship_type='mitigates',
                            user_id='demo-user', username='demo'
                        )
                        relations_created += 1
                        print(f"   ✓ Course of Action → mitigates → Malware")
                    except: pass
        
        print(f"\n   Total relationships created: {relations_created}")
        
        # ============================================================
        # PHASE 3: Create Cases and Incidents (linked to scenarios)
        # ============================================================
        print("\n" + "=" * 60)
        print("PHASE 3: Creating Cases and Incidents")
        print("=" * 60)
        
        case_service = CaseService()
        incident_service = IncidentService()
        cases_data = generate_coherent_cases_and_incidents(scenario_objects)
        
        created_cases = []
        created_incidents = []
        
        for case_config in cases_data:
            scenario_key = case_config.get('scenario')
            scenario_objs = scenario_objects.get(scenario_key, {})
            
            # Collect IOCs for this case from its scenario
            case_iocs = []
            if 'indicators' in scenario_objs:
                case_iocs.extend(scenario_objs['indicators'])
            if 'malware' in scenario_objs:
                case_iocs.extend(scenario_objs['malware'])
            if 'infrastructure' in scenario_objs:
                case_iocs.extend(scenario_objs['infrastructure'])
            
            try:
                case_data = {
                    'title': case_config['title'],
                    'description': case_config['description'],
                    'status': case_config['status'],
                    'priority': case_config['priority'],
                    'severity': case_config['severity'],
                    'case_type': case_config['case_type'],
                    'tags': case_config['tags'],
                    'tlp': case_config['tlp'],
                    'ioc_ids': case_iocs[:10]  # Link first 10 relevant IOCs
                }
                
                case = case_service.create_case(case_data, 'demo_user', 'Demo User')
                created_cases.append({'case': case, 'scenario': scenario_key})
                print(f"\n   ✓ Case: {case_config['title']}")
                
                # Create incidents for this case
                for inc_config in case_config.get('incidents', []):
                    try:
                        # Get subset of IOCs for this incident
                        incident_iocs = case_iocs[:5] if case_iocs else []
                        
                        incident_data = {
                            'case_id': case['id'],
                            'title': inc_config['title'],
                            'description': inc_config['description'],
                            'status': inc_config['status'],
                            'severity': inc_config['severity'],
                            'category': inc_config['category'],
                            'ioc_ids': incident_iocs,
                            'affected_assets': inc_config.get('affected_assets', ''),
                            'attack_vector': inc_config.get('attack_vector', 'network'),
                            'mitre_tactics': inc_config.get('mitre_tactics', []),
                            'mitre_techniques': inc_config.get('mitre_techniques', [])
                        }
                        
                        incident = incident_service.create_incident(incident_data, 'demo_user', 'Demo User')
                        created_incidents.append(incident)
                        print(f"      ✓ Incident: {inc_config['title']}")
                    except Exception as e:
                        print(f"      ✗ Incident error: {e}")
                
            except Exception as e:
                print(f"   ✗ Case error: {e}")
        
        print(f"\n   Created {len(created_cases)} cases with {len(created_incidents)} incidents")
        
        # ============================================================
        # PHASE 4: Create Users, API Keys, and Other Resources
        # ============================================================
        print("\n" + "=" * 60)
        print("PHASE 4: Creating Users and Resources")
        print("=" * 60)
        
        # Create demo users with different roles
        print("\n4. Creating demo users with different roles...")
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
                    print(f"   ✓ Created {role:20s} | {username}")
                else:
                    print(f"   → User {username} already exists")
            except Exception as e:
                print(f"   ✗ Failed to create user {username}: {str(e)}")
        
        print(f"   Created {len(created_users)} users")
        
        # Create API keys
        print("\n5. Creating API keys...")
        api_keys_created = 0
        api_key_user_id = None
        for user in created_users[:1]:
            try:
                key, key_obj = APIKey.create(user.id, 'Demo API Key')
                api_keys_created += 1
                api_key_user_id = user.id
                print(f"   ✓ Created API key for user: {user.username}")

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
        
        # Create checklist templates
        print("\n9. Creating checklist templates...")
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
                    print(f"   Created template: {template_data['name']}")
                except Exception as e:
                    print(f"      Warning: Failed to create template '{template_data['name']}': {str(e)}")
        except Exception as e:
            print(f"      Warning: Failed to generate templates: {str(e)}")
        
        print(f"   ✓ Created {templates_created} checklist templates")
        
        # Create demo checklists
        print("\n10. Creating demo checklists...")
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
                    print(f"   Created checklist: {checklist_data['title']}")
                except Exception as e:
                    print(f"      Warning: Failed to create checklist '{checklist_data['title']}': {str(e)}")
        except Exception as e:
            print(f"      Warning: Failed to generate checklists: {str(e)}")
        
        print(f"   ✓ Created {checklists_created} checklists")
        
        # Create relationships between checklists and cases (prefer checklists that match case tags for coherence)
        print("\n10a. Linking checklists to cases...")
        checklist_case_relations = 0
        
        try:
            # Get checklist metadata from ES so we can match by tags/title
            checklists_info = []
            try:
                es_service = ElasticsearchService()
                checklists_result = es_service.search('checklists', {
                    "size": 200,
                    "query": {"match_all": {}}
                })
                if checklists_result and 'hits' in checklists_result:
                    for hit in checklists_result['hits']['hits']:
                        src = hit.get('_source', {})
                        checklists_info.append({
                            'id': hit['_id'],
                            'title': src.get('title', ''),
                            'tags': src.get('tags', [])
                        })
            except Exception as e:
                print(f"      Warning: Could not fetch checklists metadata: {str(e)}")
            
            comment_service = CommentService()

            # Link 1-2 relevant checklists to each case
            if checklists_info:
                for case in created_cases:
                    try:
                        # Support both stored shapes: either case is a dict with key 'case' or a raw case dict
                        case_obj = case.get('case') if isinstance(case, dict) and 'case' in case else case
                        case_tags = set(case_obj.get('tags', []) or [])

                        # Prefer checklists that share tags with the case
                        candidates = [c for c in checklists_info if case_tags.intersection(set(c.get('tags', [])))]
                        if not candidates:
                            # fallback to checklists with generic incident/case tag
                            candidates = [c for c in checklists_info if 'incident' in c.get('tags', []) or 'case' in c.get('tags', [])]
                        if not candidates:
                            candidates = checklists_info

                        num_checklists = random.randint(1, min(2, len(candidates)))
                        selected_checklists = random.sample(candidates, num_checklists)

                        for checklist in selected_checklists:
                            try:
                                # Create a relationship document between case and checklist (include a bit of context)
                                relation_id = str(uuid.uuid4())
                                relation = {
                                    'source_type': 'case',
                                    'source_id': case_obj['id'],
                                    'target_type': 'checklist',
                                    'target_id': checklist['id'],
                                    'relation_type': 'uses_checklist',
                                    'context': {'case_title': case_obj.get('title', '')},
                                    'created_at': datetime.utcnow().isoformat(),
                                    'created_by': 'demo_user'
                                }
                                es_service.index('case_checklist_relations', relation_id, relation)
                                checklist_case_relations += 1

                                # Add a comment to the case noting the assigned checklist for traceability
                                try:
                                    comment_service.create_comment(
                                        target_id=case_obj['id'],
                                        target_type='case',
                                        content=f"Assigned checklist '{checklist['title']}' to this case.",
                                        user_id='demo_user',
                                        username='Demo Analyst'
                                    )
                                except Exception:
                                    pass

                            except Exception as e:
                                print(f"         Warning: Failed to link checklist to case: {str(e)}")
                    except Exception as e:
                        print(f"      Warning: Error processing case for checklist linking: {str(e)}")
        except Exception as e:
            print(f"      Warning: Failed to create case-checklist relationships: {str(e)}")
        
        print(f"   ✓ Created {checklist_case_relations} case-checklist relationships")
        
        # Create relationships between checklists and incidents (prefer checklists matching incident tags/campaigns)
        print("\n10b. Linking checklists to incidents...")
        checklist_incident_relations = 0
        
        try:
            # Reuse checklists_info from above (if built) otherwise fetch
            if 'checklists_info' not in locals() or not checklists_info:
                checklists_info = []
                try:
                    es_service = ElasticsearchService()
                    checklists_result = es_service.search('checklists', {
                        "size": 200,
                        "query": {"match_all": {}}
                    })
                    if checklists_result and 'hits' in checklists_result:
                        for hit in checklists_result['hits']['hits']:
                            src = hit.get('_source', {})
                            checklists_info.append({
                                'id': hit['_id'],
                                'title': src.get('title', ''),
                                'tags': src.get('tags', [])
                            })
                except Exception as e:
                    print(f"      Warning: Could not fetch checklists metadata: {str(e)}")

            comment_service = CommentService()

            if checklists_info:
                for incident in created_incidents:
                    try:
                        incident_obj = incident.get('incident') if isinstance(incident, dict) and 'incident' in incident else incident
                        incident_tags = set(incident_obj.get('tags', []) or [])
                        incident_campaigns = set(incident_obj.get('campaigns', []) or [])

                        # Prefer checklists that share tags or campaigns
                        candidates = [c for c in checklists_info if incident_tags.intersection(set(c.get('tags', [])))]
                        if not candidates:
                            # fallback to checklists that mention campaigns or generic incident tag
                            candidates = [c for c in checklists_info if incident_campaigns.intersection(set(c.get('tags', []))) or 'incident' in c.get('tags', [])]
                        if not candidates:
                            candidates = checklists_info

                        num_checklists = random.randint(1, min(2, len(candidates)))
                        selected_checklists = random.sample(candidates, num_checklists)

                        for checklist in selected_checklists:
                            try:
                                relation_id = str(uuid.uuid4())
                                relation = {
                                    'source_type': 'incident',
                                    'source_id': incident_obj['id'],
                                    'target_type': 'checklist',
                                    'target_id': checklist['id'],
                                    'relation_type': 'uses_checklist',
                                    'context': {'incident_title': incident_obj.get('title', '')},
                                    'created_at': datetime.utcnow().isoformat(),
                                    'created_by': 'demo_user'
                                }
                                es_service.index('incident_checklist_relations', relation_id, relation)
                                checklist_incident_relations += 1

                                # Add a comment to the incident noting the assigned checklist for traceability
                                try:
                                    comment_service.create_comment(
                                        target_id=incident_obj['id'],
                                        target_type='incident',
                                        content=f"Assigned checklist '{checklist['title']}' to this incident.",
                                        user_id='demo_user',
                                        username='Demo Analyst'
                                    )
                                except Exception:
                                    pass

                            except Exception as e:
                                print(f"         Warning: Failed to link checklist to incident: {str(e)}")
                    except Exception as e:
                        print(f"      Warning: Error processing incident for checklist linking: {str(e)}")
        except Exception as e:
            print(f"      Warning: Failed to create incident-checklist relationships: {str(e)}")
        
        print(f"   ✓ Created {checklist_incident_relations} incident-checklist relationships")
        
        # Create additional relationships between incidents within the same case
        print("\n10c. Creating multi-incident relationships within cases...")
        incident_to_incident_relations = 0
        
        try:
            for case in created_cases:
                # Find incidents belonging to this case
                case_incidents = [inc for inc in created_incidents if inc.get('case_id') == case['id']]
                
                if len(case_incidents) > 1:
                    # Create relationships between pairs of incidents in the same case
                    for i in range(len(case_incidents)):
                        for j in range(i + 1, min(i + 3, len(case_incidents))):
                            try:
                                relation_id = str(uuid.uuid4())
                                relation = {
                                    'source_type': 'incident',
                                    'source_id': case_incidents[i]['id'],
                                    'target_type': 'incident',
                                    'target_id': case_incidents[j]['id'],
                                    'relation_type': random.choice(['related', 'part_of_same_campaign', 'sequential_activity', 'shared_infrastructure']),
                                    'case_id': case['id'],
                                    'created_at': datetime.utcnow().isoformat(),
                                    'created_by': 'demo_user'
                                }
                                es_service.index('incident_relations', relation_id, relation)
                                incident_to_incident_relations += 1
                            except Exception as e:
                                print(f"         Warning: Failed to create incident-to-incident relationship: {str(e)}")
        except Exception as e:
            print(f"      Warning: Failed to create incident-to-incident relationships: {str(e)}")
        
        print(f"   ✓ Created {incident_to_incident_relations} incident-to-incident relationships")
        
        # Create timeline events (audit log entries)
        print("\n11. Creating timeline events...")
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
        
        # Add comments to cases
        print("\n12. Adding comments to cases...")
        comment_service = CommentService()
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
                print(f"      Warning: Failed to add comment to case: {str(e)}")
        
        print(f"   ✓ Added {case_comments_created} comments to cases")
        
        # Add comments to incidents
        print("\n13. Adding comments to incidents...")
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
                print(f"      Warning: Failed to add comment to incident: {str(e)}")
        
        print(f"   ✓ Added {incident_comments_created} comments to incidents")
        
        print("\n" + "=" * 60)
        print("Demo data population complete!")
        print(f"Total STIX objects created: {len(all_created_ids)}")
        print(f"Total STIX relationships: {relations_created}")
        print(f"Total cases created: {len(created_cases)}")
        print(f"Total incidents created: {len(created_incidents)}")
        print(f"Total demo users created: {len(created_users)}")
        print(f"Total API keys created: {api_keys_created}")
        print(f"Total external API configs: {external_api_created}")
        print(f"Total webhooks created: {webhooks_created}")
        print(f"Total snippets created: {snippets_created}")
        print(f"Total checklist templates created: {templates_created}")
        print(f"Total checklists created: {checklists_created}")
        print("=" * 60)


if __name__ == '__main__':
    populate_demo_data()