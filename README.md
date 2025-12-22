# ElasMISP

A lightweight MISP alternative for managing Indicators of Compromise (IOCs) with Elasticsearch backend. Supports STIX 2.1, MISP, OpenIOC, and IODEF formats.

## Features

- **STIX 2.1 Native**: Uses STIX 2.1 as internal format with strict validation
- **Multi-format Import**: Bulk import from STIX, MISP JSON, OpenIOC, and IODEF files
- **Simple IOC Entry**: Form-based input with automatic STIX pattern generation
- **IOC Relationships**: Link IOCs with relationship types (related-to, indicates, etc.)
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

- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- IPv4 addresses
- Domains
- Email addresses
- URLs

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
```bash
docker-compose up -d
```

4. Access the application:
- Web UI: http://localhost:5000
- API Documentation: http://localhost:5000/apidocs (requires login)

5. Create your first admin user by running the initialization script or contact your administrator

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
| `ELASTICSEARCH_URL` | Elasticsearch URL | `http://elasticsearch:9200` |
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
