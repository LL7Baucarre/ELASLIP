# ElasMISP

A lightweight MISP alternative for managing Indicators of Compromise (IOCs) with Elasticsearch backend. Supports STIX 2.1, MISP, OpenIOC, and IODEF formats.

![ElasMISP Demo](.github/demo.gif)

## Key Highlights

✨ **What's Included:**
- 📊 **Interactive Dashboard** - Real-time IOC statistics and metrics
- 🔍 **Advanced Search** - Full-text and pattern-based search capabilities
- 📈 **IOC Graph** - Visual relationship mapping with Cytoscape.js
- 🎯 **Risk Scoring** - Automatic composite risk score calculation
- 📋 **Bulk Operations** - Manage multiple IOCs at once
- 🔐 **Secure API** - Token-based authentication with encrypted keys
- 📅 **Versioning** - Complete version history with restore capabilities
- 🚨 **Activity Timeline** - Comprehensive audit trail of all actions
- 🌙 **Dark Mode** - Eye-friendly dark theme support
- 📦 **Import/Export** - Support for STIX, MISP, OpenIOC, and IODEF formats

## Features

### Core Features
- **STIX 2.1 Native**: Uses STIX 2.1 as internal format with strict validation
- **Multi-format Import**: Bulk import from STIX, MISP JSON, OpenIOC, and IODEF files
- **Simple IOC Entry**: Form-based input with automatic STIX pattern generation
- **IOC Relationships**: Link IOCs with relationship types (related-to, indicates, etc.)
- **IOC Metadata**: Track confidence levels, TLP (Traffic Light Protocol), and related campaigns
- **Interactive Graph Visualization**: Visualize IOC relationships with graph view
- **Deduplication**: Automatic deduplication with source tracking
- **External API Integration**: Enrich IOCs with configurable external APIs (VirusTotal, AbuseIPDB, etc.)
- **Webhooks**: Real-time notifications on IOC events
- **Search**: Full-text and pattern-based search
- **API Keys**: Secure programmatic access with API key authentication
- **Admin User Management**: Admin-only user creation and management (no public registration)
- **Interactive API Documentation**: Swagger UI for exploring and testing APIs
- **Site Configuration**: Customizable site name and title
- **Password Management**: Secure password change functionality
- **Dockerized**: Complete Docker Compose setup for easy deployment

### Advanced Features

#### Risk Scoring
Automatic composite risk score calculation (0-100) based on:
- **Threat Level** (45% weight): unknown=0, low=20, medium=50, high=80, critical=100
- **Confidence** (35% weight): low=25, medium=50, high=75, very-high=100
- **TLP** (20% weight): white=25, green=50, amber=75, red=100

Risk scores are displayed as color-coded badges in the IOC list.

#### IOC Versioning
- Full version history for each IOC
- View changes between versions
- Restore IOCs to any previous version
- Audit trail for all modifications

#### Bulk Operations
- Select multiple IOCs using checkboxes
- Bulk update TLP, threat level, or status
- Bulk delete selected IOCs
- Bulk export to JSON, CSV, or STIX format

#### IOC Expiration Automation
- Set validity dates (valid_from, valid_until) for IOCs
- Automatic detection of expired IOCs
- View IOCs expiring soon (within N days)
- Automatic archival of expired IOCs via scheduled task

#### Activity Timeline
- Real-time activity feed showing all user actions
- Filter by action type, entity type, user, or date range
- View audit statistics and trends
- Track entity history over time

#### Dark Mode
- Toggle between light and dark themes
- Theme preference saved in browser
- Accessible from sidebar toggle

#### Incident Management System
- **Cases**: Create and manage investigation cases with detailed metadata
- **Incidents**: Link incidents to cases for organized incident response
- **Investigation Timeline**: Record and track events chronologically with timestamps and metadata
- **IOC Linking**: Associate Indicators of Compromise with incidents for comprehensive analysis
- **Comments**: Collaborative discussion on incidents with timestamped comments
- **Incident Reports**: Markdown-based reports with:
  - Simple markdown editor for flexible content creation
  - Live preview with integrated timeline visualization
  - Export to markdown files with full timeline and metadata
  - Snippet insertion for reusable report templates
- **Reusable Snippets**: 
  - Create markdown snippets for common report sections
  - User-defined categories (no predefined categories)
  - Global snippets shareable across team
  - Quick insertion into incident reports
- **Status Management**: Track incident status through lifecycle (detected → contained → recovered → closed)
- **Assignment**: Assign incidents to team members for accountability
- **Audit Logging**: Complete audit trail of all incident activities

#### Redis Caching
- Cached IOC statistics for improved dashboard performance
- Search results caching
- Automatic cache invalidation on IOC changes

#### Encryption at Rest
- API tokens encrypted using Fernet symmetric encryption
- Key derived from SECRET_KEY using PBKDF2
- Transparent encryption/decryption for sensitive data

## Supported IOC Types

### File Hashes
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

### Network Indicators
- IPv4 addresses
- IPv6 addresses
- Domains
- Email addresses
- URLs
- ASN (Autonomous System Numbers)

### TAXII Indicators
- File Path - File paths and names (e.g., `C:\Windows\System32\cmd.exe`)
- Process Name - Executable process names (e.g., `svchost.exe`)
- Registry Key - Registry key paths (e.g., `HKEY_LOCAL_MACHINE\Software\Microsoft`)
- Windows Registry Key - Windows registry keys with HKEY prefix
- Mutex - Mutex identifiers (e.g., `Global\MyMutex`)
- Certificate Serial - X.509 certificate serial numbers (e.g., `01:23:45:67:89:AB:CD:EF`)

## IOC Metadata

Each IOC can include the following metadata:

### Threat Level
Severity assessment of the indicator:
- `critical` - Imminent threat
- `high` - Significant threat
- `medium` - Moderate threat
- `low` - Minor threat
- `unknown` - Not assessed

### Confidence Level
Trust in the accuracy of the indicator:
- `low` - Low confidence
- `medium` - Medium confidence
- `high` - High confidence
- `very-high` - Very high confidence

### TLP (Traffic Light Protocol)
Classification for sharing restrictions:
- `white` - Unlimited distribution
- `green` - Community distribution
- `amber` - Restricted to organization
- `red` - Not for distribution

### Campaigns
Related campaigns or operations (comma-separated list of campaign names)

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.14+ with requierements for local development 

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ElasMISP
```

2. Create environment file:
```bash
cp .env.example .env
# Edit .env with your settings
```

3. Start the services:

**Option A: With included Elasticsearch (default)**
```bash
docker-compose up -d
```

**Option B: With external Elasticsearch instance**
If you already have Elasticsearch installed elsewhere, use:
```bash
docker-compose -f docker-compose.external-elasticsearch.yml up -d
```

Update your `.env` file with your Elasticsearch connection details:
```env
ELASTICSEARCH_URL=http://user:password@your-elasticsearch-host:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=your-password
```

4. Access the application:
- **Web UI**: http://localhost:5000
- **API Documentation**: http://localhost:5000/apidocs (requires login)
- **IOC Graph**: http://localhost:5000/iocs/graph (requires login)
- **Dashboard**: Shows real-time IOC statistics and recent activities

5. Create your first admin user:
```bash
docker-compose exec app python scripts/create_admin.py
```

6. **Generate Demo Data** (optional, for testing):
```bash
# Enable demo data in .env
export DEMO_DATA_ENABLED=true
docker-compose exec app python scripts/demo_data.py
```
This will create 100 realistic IOCs with various types, campaigns, and relationships.

### Default Credentials

After running the admin script, you can log in with the credentials you set.

> **Note**: No public registration is available. Only admins can create new user accounts.

## Graph Visualization

The IOC Graph view provides an interactive visualization of IOC relationships using Cytoscape.js:

### Features
- **Visual Relationships**: See connections between IOCs with directional arrows
- **Color-Coded Types**: Each IOC type has a distinct color for easy identification
- **Threat Level Highlighting**: Visual indication of IOC threat levels
- **Relation Labels**: Display relationship types on edges (toggle with checkbox)
- **Type Filtering**: Filter to view IOCs of specific types and their relationships
- **Layout Options**: Switch between multiple layout algorithms (COSE, Circle, Grid, etc.)
- **Node Information**: Click any IOC to view metadata (threat level, confidence, TLP, campaigns)
- **Zoom & Pan**: Full control over graph navigation
- **Threat Highlighting**: Quickly identify critical and high-threat indicators
- **Smart Search**: Find IOCs quickly with intelligent search and dropdown results
- **Show All IOCs**: Display entire IOC dataset in one view
- **Relation Filtering**: Option to show only IOCs with active relationships
- **Guided Workflow**: Empty graph on load with guidance - search drives visualization

### Accessing the Graph
1. Navigate to "IOC Graph" in the main menu
2. Click the search input to see the "Show All IOCs" option
3. Type to search for specific IOCs (10 results shown with auto-complete)
4. Select an IOC or click "Show All IOCs" to populate the graph
5. Use controls to adjust layout, toggle labels, and filter by type
6. Click any node to see detailed information
7. Double-click to navigate to the IOC detail page

## IOC List Features

The IOC list provides comprehensive management capabilities:

### Column Sorting
Click any column header to sort:
- **Type** - IOC type (IPv4, Domain, Email, etc.)
- **Pattern / Value** - The IOC indicator value
- **Risk Score** - Calculated risk severity (0-100)
- **TLP** - Traffic Light Protocol classification
- **Threat Level** - Severity assessment
- **Confidence** - Indicator accuracy confidence
- **Sources** - Number of sources referencing the IOC
- **Links** - Number of relationships with other IOCs
- **Created** - Creation timestamp

Sort order toggles between ascending and descending with visual indicators.

### Bulk Actions
- Select multiple IOCs using checkboxes
- Bulk update TLP, threat level, or status
- Bulk delete selected IOCs
- Bulk export to JSON format

## Admin Features

Admin users have access to additional management features:

- **User Management**: Create, edit, and delete user accounts
- **Site Configuration**: Customize site name and title
- **API Key Management**: Generate and revoke API keys for programmatic access
- **External API Configuration**: Set up integrations with threat intelligence services
- **Webhook Management**: Configure real-time notifications
- **System Settings**: Access to all configuration options

Access admin features through the "Admin" section in the navigation menu (visible only to admin users).

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Web Browser   │     │   API Clients   │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │     Flask App         │
         │   (Authentication)    │
         └───────────┬───────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐      ┌─────▼─────┐    ┌─────▼─────┐
│ Redis │      │Elasticsearch│   │  Celery   │
│(Cache)│      │ (Database)  │   │ (Tasks)   │
└───────┘      └─────────────┘   └───────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | Random |
| `JWT_SECRET_KEY` | JWT signing key | Random |
| `ELASTICSEARCH_URL` | Elasticsearch URL with auth | `http://elastic:elastic123@elasticsearch:9200` |
| `ELASTICSEARCH_USER` | Elasticsearch username | `elastic` |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch password | `elastic123` |
| `ELASTICSEARCH_MEMORY_XMS` | Elasticsearch min heap memory | `256m` |
| `ELASTICSEARCH_MEMORY_XMX` | Elasticsearch max heap memory | `256m` |
| `REDIS_URL` | Redis URL | `redis://redis:6379/0` |
| `FLASK_ENV` | Environment mode | `production` |
| `DEBUG` | Debug mode | `false` |
| `SITE_NAME` | Site name displayed in UI | `ElasMISP` |
| `SITE_TITLE` | Site title in browser tab | `ElasMISP` |
| `ENCRYPTION_KEY` | Key for encrypting sensitive data | Falls back to SECRET_KEY |

## API Documentation

ElasMISP provides comprehensive API documentation through an interactive Swagger UI interface. Access it at `http://localhost:5000/apidocs` after logging in.

### Authentication

All API endpoints require authentication via:
- **Session**: For web UI (cookie-based)
- **API Key**: For programmatic access via `X-API-Key` header

### Signature Verification

If a secret is configured, payloads are signed with HMAC-SHA256:

```
X-Webhook-Signature: sha256=<signature>
```

Verify in Python:
```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Docker Deployment

### Standard Deployment (Elasticsearch included)

Use `docker-compose.yml` for a complete, self-contained deployment with Elasticsearch, Redis, and the application:

```bash
docker-compose up -d
```

### Using External Elasticsearch Instance

Use `docker-compose.external-elasticsearch.yml` if you already have Elasticsearch installed on another server:

```bash
docker-compose -f docker-compose.external-elasticsearch.yml up -d
```

Configure your Elasticsearch connection in `.env`:
```env
ELASTICSEARCH_URL=http://user:password@your-elasticsearch-host:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=your-password
```

This configuration includes only the Flask app, Celery worker, and Redis cache - Elasticsearch management is external.

## Development

### Local Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Start Elasticsearch and Redis (Docker)
docker-compose up -d elasticsearch redis

# Run Flask app
flask run --debug
```

## Elasticsearch Indices

- `ioc` - IOC indicators (includes risk_score, status, current_version fields)
- `ioc_relations` - IOC relationship mappings
- `ioc_versions` - IOC version history and snapshots
- `users` - User accounts
- `api_keys` - API keys
- `api_configs` - External API configurations
- `webhooks` - Webhook configurations
- `webhook_logs` - Webhook delivery logs
- `enrichment_cache` - API response cache
- `import_jobs` - Import job tracking
- `audit_logs` - Activity timeline and audit trail
- `cases` - Investigation cases with metadata
- `incidents` - Security incidents with reports and metadata
- `timeline_events` - Investigation timeline events
- `comments` - Incident comments and discussions
- `snippets` - Reusable report snippets

## API Endpoints

### IOC Management
- `POST /api/ioc` - Create IOC
- `GET /api/ioc` - List IOCs with filters
- `GET /api/ioc/<id>` - Get IOC details
- `PUT /api/ioc/<id>` - Update IOC
- `DELETE /api/ioc/<id>` - Delete IOC

### Case Management
- `POST /api/cases` - Create case
- `GET /api/cases` - List cases with filters
- `GET /api/cases/<id>` - Get case details
- `PUT /api/cases/<id>` - Update case
- `DELETE /api/cases/<id>` - Delete case

### Incident Management
- `POST /api/cases/<case_id>/incidents` - Create incident linked to case
- `GET /api/cases/<case_id>/incidents` - List incidents for a case
- `GET /api/incidents/<id>` - Get incident details
- `PUT /api/incidents/<id>` - Update incident
- `DELETE /api/incidents/<id>` - Delete incident
- `PUT /api/incidents/<id>/status` - Update incident status
- `PUT /api/incidents/<id>/report` - Update incident report (markdown)

### Investigation Timeline
- `GET /api/timeline/incident/<id>` - Get incident timeline events
- `GET /api/timeline/case/<id>` - Get case timeline events
- `POST /api/timeline/incident/<id>` - Add timeline event to incident
- `POST /api/timeline/case/<id>` - Add timeline event to case
- `GET /api/timeline/event/<id>` - Get timeline event details
- `PUT /api/timeline/event/<id>` - Update timeline event
- `DELETE /api/timeline/event/<id>` - Delete timeline event

### IOC Linking to Incidents
- `POST /api/incidents/<id>/iocs` - Link IOC to incident
- `DELETE /api/incidents/<id>/iocs/<ioc_id>` - Unlink IOC from incident
- `POST /api/cases/<id>/iocs` - Link IOC to case
- `DELETE /api/cases/<id>/iocs/<ioc_id>` - Unlink IOC from case

### Comments
- `POST /api/comments/incident/<id>` - Add comment to incident
- `GET /api/comments/incident/<id>` - Get incident comments
- `DELETE /api/comments/<id>` - Delete comment

### Snippets
- `GET /api/snippets` - List snippets
- `POST /api/snippets` - Create snippet
- `GET /api/snippets/<id>` - Get snippet details
- `PUT /api/snippets/<id>` - Update snippet
- `DELETE /api/snippets/<id>` - Delete snippet
- `GET /api/snippets/categories` - Get snippet categories with counts
- `POST /api/snippets/<id>/use` - Increment snippet usage
- `GET /api/snippets/<id>/export` - Export snippet as markdown

### Versioning
- `GET /api/ioc/<id>/versions` - Get version history
- `POST /api/ioc/<id>/versions/<version>/restore` - Restore to version

### Bulk Operations
- `POST /api/ioc/bulk/update` - Bulk update IOCs
- `POST /api/ioc/bulk/delete` - Bulk delete IOCs
- `POST /api/ioc/bulk/export` - Bulk export IOCs

### Expiration
- `GET /api/ioc/expired` - List expired IOCs
- `GET /api/ioc/expiring-soon?days=7` - IOCs expiring soon
- `POST /api/ioc/archive-expired` - Archive expired IOCs

### Audit & Timeline
- `GET /api/audit/logs` - List audit logs
- `GET /api/audit/entity/<type>/<id>` - Entity history
- `GET /api/audit/my-activity` - Current user's activity
- `GET /api/audit/stats` - Audit statistics

## Scheduled Tasks

The following Celery tasks can be scheduled:

| Task | Description | Recommended Schedule |
|------|-------------|---------------------|
| `tasks.check_expired_iocs` | Archive expired IOCs | Daily |
| `tasks.check_expiring_soon` | Notify about expiring IOCs | Daily |
| `tasks.cleanup_old_versions` | Remove old version snapshots | Weekly |
| `tasks.update_risk_scores` | Recalculate all risk scores | On demand |
| `tasks.cleanup_old_audit_logs` | Remove old audit logs | Monthly |

## Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Change the port in docker-compose.yml or use environment variable
docker-compose -e "FLASK_PORT=5001" up -d
```

**Elasticsearch Connection Error**
```bash
# Check if Elasticsearch is running
docker-compose logs elasticsearch

# Verify connection
curl -u elastic:elastic123 http://localhost:9200
```

**IOC Creation Fails with STIX Pattern Error**
- Ensure the IOC value format is valid for its type
- Supported types are: `ipv4`, `domain`, `email`, `url`, `md5`, `sha1`, `sha256`, `asn`
- Other types (process-name, registry-key, etc.) are not supported in this version

**Demo Data Generation Issues**
```bash
# Ensure DEMO_DATA_ENABLED is set
docker-compose exec app python scripts/demo_data.py

# Check container logs for details
docker-compose logs app
```

### Getting Help

1. Check the [API Documentation](http://localhost:5000/apidocs)
2. Review [Activity Timeline](http://localhost:5000/activity) for error details
3. Check Docker logs: `docker-compose logs app`
4. Enable debug mode in `.env`: `DEBUG=true`

## Performance Tips

- **Large Datasets**: Use the graph's search and filter features instead of loading all IOCs
- **Caching**: Risk scores are cached automatically - force refresh via admin panel if needed
- **Elasticsearch**: Allocate more memory in `.env` for better performance with 10k+ IOCs
- **Database**: Regular cleanup of old versions keeps indices lean

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
