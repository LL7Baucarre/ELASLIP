# ElasMISP

A lightweight MISP alternative for managing Indicators of Compromise (IOCs) with Elasticsearch backend. Supports STIX 2.1, MISP, OpenIOC, and IODEF formats.

## Features

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
- Web UI: http://localhost:5000
- API Documentation: http://localhost:5000/apidocs (requires login)
- IOC Graph: http://localhost:5000/iocs/graph (requires login)

5. Create your first admin user by running the initialization script or contact your administrator

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

### Accessing the Graph
1. Navigate to "IOC Graph" in the main menu
2. Load IOCs using the "Reload Graph" button
3. Use controls to adjust layout, toggle labels, and filter by type
4. Click any node to see detailed information
5. Double-click to navigate to the IOC detail page

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

- `ioc` - IOC indicators
- `ioc_relations` - IOC relationship mappings
- `users` - User accounts
- `api_keys` - API keys
- `api_configs` - External API configurations
- `webhooks` - Webhook configurations
- `webhook_logs` - Webhook delivery logs
- `enrichment_cache` - API response cache
- `import_jobs` - Import job tracking

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
