# Changelog



## [1.3.1] - 2026-01-08

### Added
- **VPN Split-Routing Architecture**: Worker container can route all traffic through VPN tunnel for anonymous enrichment and external API calls
  - Uses Gluetun sidecar pattern with `network_mode: service:vpn`
  - Maintains internal network access to Redis/Elasticsearch
  - Supports both OpenVPN and WireGuard
- **URL Scan Tool**: New reconnaissance tool for URL analysis and scanning
  - Automated URL scanning with security assessment
  - Integration with Celery for asynchronous processing
  - Results stored in scan history for IOC conversion
- **Docker Compose VPN configurations**:
  - `docker-compose.vpn.yml`: Embedded Elasticsearch with VPN worker routing
  - `docker-compose.external-elasticsearch.vpn.yml`: External Elasticsearch with VPN worker routing
- **VPN Configuration directory**: `/vpn` folder with comprehensive setup documentation
  - Support for custom OpenVPN (`.ovpn`) files
  - Support for WireGuard configuration
  - Automatic Gluetun healthcheck for safe startup sequencing
- **VPN environment variables**:
  - `VPN_SERVICE_PROVIDER`: VPN provider selection (custom, mullvad, protonvpn, etc.)
  - `VPN_TYPE`: Protocol selection (openvpn, wireguard)
  - `VPN_USER` / `VPN_PASSWORD`: Credentials for OpenVPN
  - `WIREGUARD_PRIVATE_KEY` / `WIREGUARD_ADDRESSES`: WireGuard configuration
  - `VPN_FIREWALL_OUTBOUND_SUBNETS`: Docker network ranges for bypass
  - `VPN_ENABLED`: Worker indicator flag
- **Documentation**: 
  - `DOCKER_COMPOSE_GUIDE.md`: Quick reference for all Docker Compose configurations
  - `vpn/README.md`: Detailed VPN setup, configuration, testing, and troubleshooting
  - Updated `README.md` with VPN configuration table and setup instructions

### Changed
- **docker-compose.yml**: Simplified to standard config (no VPN by default)
  - Worker now uses standard `networks: [ioc-network]`
  - Removed VPN service and related configuration
- **Worker container**: Renamed from hardcoded approach to flexible configuration
  - `VPN_ENABLED=false` by default in standard config
  - Set to `VPN_ENABLED=true` in VPN-enabled configs

### Architecture
- **Split-Routing Pattern**: 
  - Worker shares network namespace with VPN container
  - All outbound traffic routes through VPN tunnel
  - Inbound access to internal services (Redis, ES) preserved via firewall rules
  - App container (web UI/API) unaffected by VPN configuration

---

## [1.2.0] - 2026-01-03

### Added
- **UI: display app version**: `APP_VERSION` injected into all templates and shown as `v{{ APP_VERSION }}` in the sidebar footer
- **Dashboard: Create dropdown**: replace single "Add IOC" button with a "Create" dropdown (IOC, Case, Incident, Checklist) respecting permissions
- **Dashboard: Unresolved Public Submissions**: UI panel shows latest pending submissions (frontend + backend query) with quick access to review

### Changed
- **IOCs list**: removed quick search input and Graph View button for a cleaner toolbar
- **Templates**: use `ioc_value` for submissions display and updated table headers accordingly
- **Routes corrected**: fixed links to use existing endpoints (`main.cases_new`, `main.incidents_new`, `checklists.new_page`, `submissions.view_submission`)
- **CI triggers**: GitHub Actions build/push now runs automatically only on the `deploy` branch (and on `v*` tags)

### Fixed
- **Dashboard 500 errors**: fixed template/endpoint mismatches that caused rendering failures

---

## [1.2.0] - 2026-01-03

### Added
- **Versioning system**: Application version now configurable via `APP_VERSION` environment variable and `__version__` in config
- **GitHub Container Registry (GHCR)**: Automated Docker image builds and pushes via GitHub Actions
- **Health check endpoint**: `/health` endpoint returns application status and version
- **Version API endpoint**: `/api/version` endpoint to check application version programmatically
- **Build and Push workflow**: GitHub Actions workflow for CI/CD that:
  - Builds Docker images on push to main/develop and on version tags
  - Automatically extracts version from config
  - Tags images with: version, branch, commit hash, and latest
  - Pushes images to GHCR (GitHub Container Registry)
  - Uses Docker layer caching for faster builds
- **Docker Buildx support**: Multi-platform builds ready
- **Environment configuration**: Added `APP_VERSION` to `.env.example` and docker-compose.yml

### Changed
- **Dockerfile**: Updated to accept `APP_VERSION` build argument
- **docker-compose.yml**: Added `APP_VERSION` environment variable and build args

### Documentation
- Added `VERSIONING.md`: Complete guide for version management and deployment
- Added `DOCKER_REGISTRY.md`: Instructions for using Docker images from GHCR
- Updated `.env.example`: Added `APP_VERSION` configuration

---

## Version Management

To update the version:

1. Edit `__version__` in [app/config.py](app/config.py)
2. Commit and push to `deploy` or create a `v*` tag to trigger the CI build and image publication
3. Optionally create a Git tag: `git tag v1.2.0 && git push origin v1.2.0`

See [VERSIONING.md](VERSIONING.md) for detailed information.
