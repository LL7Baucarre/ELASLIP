
# ELASLIP

**Elastic Lightweight Analytical Security & Incident Platform**

A lightweight MISP and TheHive alternative for managing Indicators of Compromise (IOCs), investigating security incidents, and organizing security operations with AI-powered insights. Features comprehensive case and incident management, security checklists with AI analysis, IOC relationship mapping, risk scoring, multi-language LLM report generation, and token usage tracking (FinOps). Supports STIX 2.1, MISP, OpenIOC, and IODEF formats with Elasticsearch backend.

  

![ELASLIP Demo](.github/demo.gif)

  

## Key Highlights


**What's Included:**

-  **Interactive Dashboard** - Real-time statistics
-  **Advanced Search** - Full-text and pattern-based search capabilities (IOCs, Cases, Incidents)
-  **IOC Graph** - Visual relationship mapping with Cases and Incidents
-  **Entity Graphs** - Visualize relationships across IOCs, Cases, and Incidents with interactive navigation
-  **Two-Factor Authentication (2FA)** - Secure login with TOTP and backup codes
-  **Public Submission Portal** - Anonymous IOC reporting and public search
-  **API** - Token-based authentication for programmatic usage
-  **Activity Timeline** - Comprehensive audit trail of all actions in app
-  **Dark Mode** - Eye-friendly dark theme support
-  **Import/Export** - Support for STIX, MISP, OpenIOC, and IODEF formats
-  **Case Management** - Organize investigations with related incidents and IOCs
-  **Incident Investigation** - Track cases, incidents, timeline events, and team collaboration
-  **AI-Powered Reports** - Generate IOC, Case, Incident, Checklist reports via LLM
-  **FinOps Dashboard** - Track LLM token usage with analytics
-  **Security Checklists** - Create, manage, and analyze security operation tasks with AI insights  
-  **Webhooks** - Real-time event notifications
-  **Notification system** - Be aware when reports are submitted by LLM

## Features
  
### Core Features

-  **Multi-format Import** - STIX, MISP JSON, OpenIOC, IODEF support
-  **Simple IOC Entry** - Form-based input with automatic STIX pattern generation
-  **IOC Relationships** - Link IOCs with relationship types
-  **IOC Metadata** - Confidence levels, TLP, campaigns tracking
-  **Interactive Graph** - Visualize IOC relationships
-  **Deduplication** - Automatic with source tracking
-  **External API Integration** - VirusTotal, AbuseIPDB, etc.
-  **Swagger UI** - Interactive API documentation
-  **Dockerized** - Complete Docker Compose setup

### Advanced Features

#### IOC Management

-  **Bulk Operations** - Select multiple, bulk update/delete/export
-  **Expiration Automation** - Set validity dates, auto-detect expired, schedule archival
-  **Enrichment Cache** - API response caching
-  **IOC Relationship Graphs** - Interactive visualization of IOC connections with related Cases and Incidents
   - **Color-coded nodes**: IOCs by type, Cases (blue squares), Incidents (red diamonds)
   - **Smart navigation**: Click nodes to navigate to entity detail pages
   - **Relationship visualization**: See all connected entities at a glance

#### Incident Management

-  **Cases & Incidents** - Organize investigation cases and incidents
-  **Investigation Timeline** - Chronological event tracking with timestamps
-  **IOC Linking** - Associate IOCs with incidents and cases
-  **Entity Relationship Graphs** - Interactive visualization showing connected IOCs, Cases, and Incidents
   - **Unified design**: Consistent styling across all entity graphs
   - **Central node highlighting**: Golden border identifies the current entity
   - **Interactive navigation**: Click to navigate between related entities
-  **Comments** - Collaborative discussion with timestamps
-  **Status Management** - Track lifecycle through investigation stages
-  **Assignment** - Assign to users
-  **Reusable Snippets** - Markdown snippets for common sections

#### AI-Powered Report Generation

-  **LLM Integration** - Ollama and OpenAI-compatible providers
-  **Report Types** - IOC, Case, Incident, Checklist reports
-  **Custom Prompts** - Define templates per report type
-  **Markdown Output** - Formatted reports
-  **Language Instruction** - Automatic language prepend
-  **Async Generation** - Background processing with progress tracking

#### LLM Token Tracking

-  **Token Counting** - Track prompt and completion tokens
-  **Dashboard** - Real-time consumption metrics in Activity page
-  **Temporal Analysis** - Token usage trends over time
-  **Report Breakdown** - Analyze by report type

#### Checklist Management

-  **Create Checklists** - Task-based security operation checklists
-  **Templates** - Reusable checklist templates
-  **Item Tracking** - Track completion status with descriptions
-  **Campaign/Case Association** - Link to campaigns, cases, incidents
-  **Team Collaboration** - Global comments with timestamps
-  **AI Analysis** - Generate analysis reports of completed checklists

#### Security & Authentication

-  **Two-Factor Authentication (2FA)** - TOTP support (Google Authenticator, Authy, etc.)
-  **Backup Codes** - Secure recovery codes for account access
-  **RBAC** - Role-Based Access Control with granular permissions
-  **Audit Logging** - Detailed tracking of all user and system actions
-  **API Key Management** - Secure programmatic access with scoped keys

#### Image Management

-  **Image Upload** - Upload and attach images to IOCs, Cases, Incidents, and Checklists
-  **Image Viewer Modal** - Full-screen image preview with download capability
-  **Image Rename** - Rename uploaded images for better organization
-  **Image Gallery** - View all images associated with an entity
-  **File Size Limit** - 10MB per image with type validation (PNG, JPG, GIF, WebP, BMP)

#### Enrichment Tools

-  **GeoIP Tool** - Resolve IP addresses to geographic locations and organization information
-  **IP API Integration** - Automatic geographic and ASN lookup for IP indicators
-  **Location Mapping** - Visual and data-based IP geolocation

#### Public Portal

-  **Anonymous Submissions** - Allow external users to report IOCs
-  **Public Search** - Limited search interface for public verification
-  **Submission Review** - Admin workflow to validate and import public reports
-  **Configurable Access** - Enable/disable public features via environment variables

## Supported IOC Types

**Hashes**: MD5, SHA1, SHA256
**Network**: IPv4, IPv6, Domain, Email, URL, ASN
**Files/Processes**: File Path, Process Name, Registry Key, Mutex
**Other**: Certificate Serial

## Quick Start
### Prerequisites

- Docker & Docker Compose

- (Optional) Ollama for AI reports

### Installation

```bash

git  clone <repo-url>

cd  ELASLIP

cp  .env.example  .env

  

# Start with included Elasticsearch

docker-compose  up  -d

  

# Or with external Elasticsearch

docker-compose  -f  docker-compose.external-elasticsearch.yml  up  -d
 

# Initialize

docker-compose  exec  app  python  scripts/init_elasticsearch.py

  

# Create admin user

docker-compose  exec  app  python  scripts/create_admin.py

  
# One liner for quick demo start
docker compose down -v ; docker compose up -d --build ; docker compose exec app python /app/scripts/demo_data.py ; docker compose logs app worker -f

# Access

# Web: http://localhost:5000

# API: http://localhost:5000/apidocs

```

### Demo Data (Optional)

To populate the database with sample IOCs, cases, and incidents, set `DEMO_DATA_ENABLED=true` in `.env` before startup, or run manually:

```bash

docker-compose  exec  app  python  scripts/demo_data.py

```

This generates realistic test data useful for exploring features and understanding workflows.

  

## Configuration


### LLM Setup (for AI Reports)  

**Settings > LLM Settings:**

-  **LLM URL**: `http://ollama:11434` (default)

-  **Model**: `mistral` (or preferred model)

-  **Generation Language**: Select output language

-  **Custom Prompts** (optional): Template per report type

Variables: `{type}`, `{value}`, `{severity}`, `{description}`, `{relations}`, `{name}`, `{status}`, etc.

### Enrichment Tools

#### GeoIP Tool
- **Single Lookup** - Resolve an IP address to geolocation, organization, and ASN data
- **Bulk Lookup** - Lookup up to 100 IP addresses at once (one per line)
- **Source Extraction** - Automatically extract source IP from email headers and perform GeoIP lookup
- **IOC Integration** - Create IOCs directly from results with pre-populated location data
- **Result Caching** - Responses cached to minimize API calls (default: 1 hour TTL)

**Access**: Tools menu → GeoIP Lookup

**Features**:
- Displays: Country, City, Timezone, ISP/Organization, ASN, Latitude, Longitude, Mobile/Proxy/Hosting flags
- Bulk operations return summary with successful/failed counts
- Results saved to scan history for reference

#### Email Header Analyzer Tool
- **Header Parsing** - Extract key information from email headers (From, To, Subject, Date)
- **Hop Analysis** - Display complete email route showing all relay servers
- **Source IP Extraction** - Automatically identify sending server IP from Received headers
- **GeoIP Integration** - Perform GeoIP lookup on extracted source IP
- **IOC Creation** - Create IOCs from extracted recipient addresses or source IP
- **Recipient Analysis** - Extract domain from email recipients for domain-based investigation

**Access**: Tools menu → Email Headers

**Features**:
- Visual hop diagram showing email route with server information
- One-click GeoIP lookup for source IP
- Extract and create IOCs from recipients or source IP
- Supports large headers (up to 100KB)
- Email tags automatically applied to created IOCs

### IP API Integration (GeoIP Enrichment)

The application integrates with **[IP-API.com](https://ip-api.com)** for geographic and ASN information enrichment on IP addresses.

#### Features

- **Automatic GeoIP Lookup** - Resolve IP addresses to location, organization, and ASN
- **GeoIP Tool** - Manual single and bulk lookup tool available in Tools menu
- **Email Header Integration** - Extract source IPs from email headers and geolocate them
- **IP Enrichment** - Automatic enrichment when creating or importing IOCs
- **Caching** - Responses cached to minimize API calls (default: 1 hour TTL)

#### Terms of Service & Limitations

⚠️ **Important**: By using this feature, you agree to IP-API.com's Terms of Service:

- **Free Plan**: 45 requests per minute, ~1,440 per day
- **Commercial Use**: Requires paid plan at [ip-api.com/pricing](https://ip-api.com/pricing)
- **Accuracy**: Results are provided "as-is" for informational purposes
- **Attribution**: Required to include proper attribution when using IP-API data
- **Rate Limiting**: Requests exceeding the limit are blocked; upgrade for higher limits
- **Data Privacy**: Queries are logged by IP-API.com per their privacy policy

Full terms available at: [ip-api.com/docs/legal](https://ip-api.com/docs/legal)

#### Configuration

IP-API is enabled by default. To use:

1. **Manual Tool**: Navigate to **Tools > GeoIP Tool**, enter an IP address, and click "Lookup"
2. **Automatic Enrichment**: Imported or created IOCs of type `ipv4` or `ipv6` are automatically enriched
3. **View Results**: Results displayed inline with location, organization, and ASN information

**Cache Management**: Elasticsearch index `elaslip_enrichment_cache` stores results to reduce API calls.

#### Disabling IP-API

If you prefer not to use this service, disable enrichment via:

- Settings > Enrichment Settings (when available)
- Or set enrichment to "disabled" in app configuration

  


### Environment Variables
 

| Variable | Default | Description |
|---|---:|---|
| `FLASK_ENV` | `development` | Flask environment
| `FLASK_APP` | `app` | Flask application entrypoint
| `SECRET_KEY` | `your-super-secret-key-change-in-production` | Flask secret key (change in production)
| `SITE_NAME` | `ELASLIP` | Short site name
| `SITE_TITLE` | `ELASLIP` | Full site title shown in the UI
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch URL
| `ELASTICSEARCH_USER` | `elastic` | Elasticsearch username
| `ELASTICSEARCH_PASSWORD` | `elastic123` | Elasticsearch password
| `ELASTICSEARCH_MEMORY_XMS` | `256m` | ES JVM initial heap size
| `ELASTICSEARCH_MEMORY_XMX` | `256m` | ES JVM max heap size
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL (sessions/cache)
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker / result backend URL
| `DEFAULT_ADMIN_USER` | `admin` | Default admin username created on first init
| `DEFAULT_ADMIN_PASSWORD` | `admin123` | Default admin password created on first init
| `DEMO_DATA_ENABLED` | `false` | Populate demo data on first run
| `DEBUG` | `false` | Flask debug flag
| `LLM_ENABLED` | `false` | Enable AI-based report generation
| `LLM_PROVIDER` | `auto` | LLM provider type (`auto`, `ollama`, `openai`)
| `LLM_URL` | `http://ollama:11434` | LLM provider URL (Ollama / OpenAI-compatible)
| `LLM_MODEL` | `mistral` | Default LLM model
| `LLM_API_KEY` | `` | API key for OpenAI-compatible providers (optional)
| `LLM_GENERATION_LANGUAGE` | `fr` | Default language for generated reports
| `PUBLIC_SEARCH_ENABLED` | `true` | Enable public search portal
| `PUBLIC_SUBMISSIONS_SUBMIT_ENABLED` | `true` | Enable public IOC submission form
| `PUBLIC_SUBMISSIONS_MAX_RESULTS` | `10` | Max results for public search
| `PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS` | `true` | Allow submissions without account login
| `ENRICHMENT_CACHE_TTL` | `3600` | Enrichment cache time-to-live in seconds (GeoIP results)
| `GEOIP_ENABLED` | `true` | Enable IP-API.com GeoIP enrichment for IP indicators

See `.env.example` for the canonical defaults and examples.


See `http://localhost:5000/apidocs` for full API documentation.

## Docker Deployment

```bash

# Standard (with Elasticsearch)

docker-compose  up  -d

# External Elasticsearch

docker-compose  -f  docker-compose.external-elasticsearch.yml  up  -d

```

## Development


```bash

python  -m  venv  venv

source  venv/bin/activate

pip  install  -r  requirements.txt

docker-compose  up  -d  elasticsearch  redis

flask  run  --debug

```

  

## Elasticsearch Indices

  
## Elasticsearch Indices

The application uses the following Elasticsearch indices for data storage:

- `elaslip_ioc` - IOC indicators
- `elaslip_users` - User data
- `elaslip_api_keys` - API keys
- `elaslip_api_configs` - API configurations
- `elaslip_webhooks` - Webhooks
- `elaslip_webhook_logs` - Webhook logs
- `elaslip_enrichment_cache` - Enrichment cache (GeoIP results, etc.)
- `elaslip_import_jobs` - Import jobs
- `elaslip_scan_results` - Scan results
- `elaslip_ioc_relations` - IOC relationships
- `elaslip_audit_logs` - Audit logs
- `elaslip_ioc_versions` - IOC versions
- `elaslip_roles` - Roles
- `elaslip_cases` - Cases
- `elaslip_incidents` - Incidents
- `elaslip_timeline_events` - Timeline events
- `elaslip_comments` - Comments
- `elaslip_snippets` - Snippets
- `elaslip_checklists` - Checklists
- `elaslip_checklist_templates` - Checklist templates
- `elaslip_submissions` - Submissions
- `elaslip_app_config` - Application configuration
- `elaslip_finops_token_usage` - FinOps token usage
- `elaslip_images` - Uploaded images for IOCs, Cases, Incidents, and Checklists


## License

  

MIT