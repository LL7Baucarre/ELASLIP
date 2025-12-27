
# ElasMISP

  

A lightweight MISP alternative for managing Indicators of Compromise (IOCs), investigating security incidents, and organizing security operations with AI-powered insights. Features comprehensive case and incident management, security checklists with AI analysis, IOC relationship mapping, risk scoring, multi-language LLM report generation, and token usage tracking (FinOps). Supports STIX 2.1, MISP, OpenIOC, and IODEF formats with Elasticsearch backend.

  

![ElasMISP Demo](.github/demo.gif)

  

## Key Highlights


**What's Included:**

-  **Interactive Dashboard** - Real-time statistics
-  **Advanced Search** - Full-text and pattern-based search capabilities
-  **IOC Graph** - Visual relationship mapping and search
-  **API** - Token-based authentication for programmatic usage
-  **Versioning** - Complete IOC version history with restore capability
-  **Activity Timeline** - Comprehensive audit trail of all actions in app
-  **Dark Mode** - Eye-friendly dark theme support
-  **Import/Export** - Support for STIX, MISP, OpenIOC, and IODEF formats
-  **Case Management** - Organize investigations with related incidents and IOCs
-  **Incident Investigation** - Track cases, incidents, timeline events, and team collaboration
-  **AI-Powered Reports** - Generate IOC, Case, Incident, Checklist reports via LLM
-  **FinOps Dashboard** - Track LLM token usage with analytics
-  **Security Checklists** - Create, manage, and analyze security operation tasks with AI insights  
- -  **Webhooks** - Real-time event notifications

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

  
#### Risk Scoring

- Composite calculation (0-100)  

#### IOC Management

-  **Version Control** - Full history, view changes, restore previous versions
-  **Bulk Operations** - Select multiple, bulk update/delete/export
-  **Expiration Automation** - Set validity dates, auto-detect expired, schedule archival
-  **Enrichment Cache** - API response caching

#### Incident Management

-  **Cases & Incidents** - Organize investigation cases and incidents
-  **Investigation Timeline** - Chronological event tracking with timestamps
-  **IOC Linking** - Associate IOCs with incidents and cases
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


#### FinOps - LLM Token Tracking

-  **Token Counting** - Track prompt and completion tokens

-  **Dashboard** - Real-time consumption metrics in Activity page

-  **Temporal Analysis** - Token usage trends over time

-  **Report Breakdown** - Analyze by report type

-  **Cost Tracking** - Monitor by date and model

-  **API Access** - Query token data programmatically

#### Checklist Management

-  **Create Checklists** - Task-based security operation checklists

-  **Templates** - Reusable checklist templates

-  **Item Tracking** - Track completion status with descriptions

-  **Campaign/Case Association** - Link to campaigns, cases, incidents

-  **Team Collaboration** - Global comments with timestamps

-  **AI Analysis** - Generate analysis reports of completed checklists

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

cd  ElasMISP

cp  .env.example  .env

  

# Start with included Elasticsearch

docker-compose  up  -d

  

# Or with external Elasticsearch

docker-compose  -f  docker-compose.external-elasticsearch.yml  up  -d

  

# Initialize

docker-compose  exec  app  python  scripts/init_elasticsearch.py

  

# Create admin user

docker-compose  exec  app  python  scripts/create_admin.py

  

# Access

# Web: http://localhost:5000

# API: http://localhost:5000/apidocs

```

  

## Configuration

  

### LLM Setup (for AI Reports)

  

**Settings > LLM Settings:**

-  **LLM URL**: `http://ollama:11434` (default)

-  **Model**: `mistral` (or preferred model)

-  **Generation Language**: Select output language

-  **Custom Prompts** (optional): Template per report type

  

Variables: `{type}`, `{value}`, `{severity}`, `{description}`, `{relations}`, `{name}`, `{status}`, etc.

  

### Environment Variables

  

| Variable | Default |

|----------|---------|

| `ELASTICSEARCH_URL` | `http://elastic:elastic123@elasticsearch:9200` |

| `REDIS_URL` | `redis://redis:6379/0` |

| `LLM_URL` | `http://ollama:11434` |

| `LLM_MODEL` | `mistral` |

| `SECRET_KEY` | Random |

| `DEBUG` | `false` |

| `SITE_NAME` | `ElasMISP` |

  

## Usage

  

### Generate Reports

1. Go to IOC/Case/Incident/Checklist detail

2. Click **"Generate Report"**

3. Wait for processing

4. View/export markdown

  

### FinOps (Token Tracking)

1.  **Activity** page > **FinOps** tab

2. View timeline, breakdown, statistics

  

### Checklists

1.  **Checklists** > **New**

2. Select template or create

3. Track items & add comments

4. Generate AI analysis

  

## API Endpoints

  

**IOCs**: `/api/ioc` (CRUD), `/api/ioc/<id>/versions` (history)

**Cases**: `/api/cases` (CRUD)

**Incidents**: `/api/incidents` (CRUD), `/api/incidents/<id>/report`

**Timeline**: `/api/timeline/{incident|case}/<id>`

**Reports**: `/api/reports/generate/{ioc|case|incident|checklist}/<id>`

**FinOps**: `/api/finops/{timeline|breakdown|statistics|top-consumers}`

**Checklists**: `/api/checklists` (CRUD), `/api/checklists/<id>/items`

**Bulk**: `/api/ioc/bulk/{update|delete|export}`

  

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

  

-  `ioc` - IOC indicators

-  `ioc_relations` - IOC relationships

-  `ioc_versions` - Version history

-  `cases`, `incidents` - Investigation data

-  `timeline_events` - Timeline events

-  `comments` - Discussion comments

-  `snippets` - Report snippets

-  `checklists`, `checklist_templates` - Checklist data

-  `ioc_manager_finops_token_usage` - Token tracking

-  `app_config` - Application settings

-  `audit_logs` - Activity history

-  `users`, `api_keys` - Authentication

  

## Troubleshooting

  

**Elasticsearch Connection**

```bash

docker-compose  logs  elasticsearch

curl  -u  elastic:elastic123  http://localhost:9200

```

  

**LLM Issues**

- Ensure Ollama running: `ollama serve`

- Check URL in Settings

- Verify model: `ollama list`

  

**Report Generation**

- Check FinOps tab errors

- Ensure LLM can reach app

- Verify resources available

  

**More Help**: Visit API docs at `http://localhost:5000/apidocs` or enable `DEBUG=true`

  

## License

  

MIT

  

## Contributing

  

1. Fork the repository

2. Create a feature branch

3. Submit a pull request