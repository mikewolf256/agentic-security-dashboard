# Agentic Security - Live Scan Dashboard

Real-time streaming dashboard for monitoring active security scans. This is a lightweight WebSocket-based dashboard that provides live visibility into scan progress.

**For full vulnerability management, findings are exported to per-client [Faraday](https://github.com/infobyte/faraday) instances.**

## Features

- Real-time WebSocket event streaming
- Token-based authentication
- Live scan statistics (requests, endpoints, payloads, findings)
- Scan progress with phase indicators and ETA
- Tech stack fingerprint display
- Live findings feed during scan

## Architecture

```
┌─────────────────┐     WebSocket      ┌─────────────────┐
│ Agentic Runner  │ ──────────────────►│  Live Dashboard │
│                 │   POST /api/event  │  (this service) │
└─────────────────┘                    └─────────────────┘
        │                                      │
        │ findings.json                        │ real-time view
        ▼                                      ▼
┌─────────────────┐                    ┌─────────────────┐
│ Faraday Export  │                    │  Client Browser │
│                 │                    │                 │
└─────────────────┘                    └─────────────────┘
        │
        │ REST API
        ▼
┌─────────────────┐
│ Faraday Instance│
│ (vuln mgmt)     │
└─────────────────┘
```

## Quick Start

### Local Development

```bash
# Set environment variables
export DASHBOARD_TOKEN=your-secure-token

# Run with Docker Compose
docker compose up

# Or run directly
pip install -r requirements.txt
python app.py
```

Access at: http://localhost:5050

### Deploy to Fly.io (Recommended for Production)

The dashboard can be deployed to [Fly.io](https://fly.io) with persistent storage for ~$5/month:

```bash
# First-time setup
./deploy.sh setup

# Deploy
./deploy.sh deploy
```

This creates:
- A Fly.io app with persistent SQLite storage
- Automatic HTTPS/TLS
- Health checks and auto-restart
- 1GB persistent volume

**Manual Setup:**

```bash
# Install Fly CLI: https://fly.io/docs/hands-on/install-flyctl/
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Launch (first time)
fly launch --copy-config --no-deploy

# Create persistent volume (1GB)
fly volumes create agentic_data --size 1 --region ord

# Set secrets
fly secrets set DASHBOARD_TOKEN=your-secure-token
fly secrets set SECRET_KEY=$(openssl rand -hex 32)

# Deploy
fly deploy
```

Your dashboard will be at: `https://agentic-dashboard.fly.dev`

### Self-Hosted Production

```bash
# Build and run
docker compose -f docker-compose.prod.yml up -d

# Or integrate with main agentic-bugbounty deployment
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `DASHBOARD_TOKEN` | Authentication token | `changeme` |
| `PORT` | Server port | `5050` |
| `HOST` | Bind address | `0.0.0.0` |
| `CORS_ORIGINS` | Allowed origins | `*` |
| `SECRET_KEY` | Flask secret key | (random) |
| `STORAGE_BACKEND` | Storage type: `sqlite` or `memory` | `memory` |
| `SQLITE_PATH` | Path to SQLite database | `/data/dashboard.db` |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML page |
| `/health` | GET | Health check |
| `/api/stats` | GET | Current scan statistics |
| `/api/events` | GET | Recent events (auth required) |
| `/api/event` | POST | Push new event (auth required) |
| `/api/scans` | GET | Scan history (auth required) |
| `/api/scans/<scan_id>` | GET | Scan detail with findings (auth required) |
| `/api/findings` | GET | All findings (auth required) |
| `/api/dashboard-stats` | GET | Aggregated statistics (auth required) |
| `/api/scan/register` | POST | Register active scan (auth required) |
| `/api/scan/kill` | POST | Emergency stop scan (auth required) |
| `/api/scan/status` | GET | Check scan status (auth required) |

### Pushing Events

The scanner pushes events to the dashboard via POST:

```bash
curl -X POST http://localhost:5050/api/event \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "finding_validated",
    "payload": {
      "title": "XSS in search parameter",
      "severity": "high",
      "cwe": "CWE-79"
    }
  }'
```

### Event Types

| Event Type | Description |
|------------|-------------|
| `scan_start` | Scan initiated |
| `scan_complete` | Scan finished |
| `phase_start` | New phase (recon, scanning, validation) |
| `endpoint_discovered` | New endpoint found |
| `tech_fingerprint` | Technology detected |
| `payload_sent` | Test payload sent |
| `finding_candidate` | Potential finding |
| `finding_validated` | Confirmed finding |
| `rag_match` | Similar vuln from RAG |

## WebSocket Events

Connect via Socket.IO with token authentication:

```javascript
const socket = io({
    auth: { token: 'your-token' },
    transports: ['websocket', 'polling']
});

socket.on('scan_event', (event) => {
    console.log('Event:', event);
});

socket.on('stats_update', (stats) => {
    console.log('Stats:', stats);
});
```

## Integration with Faraday

This dashboard is for **real-time monitoring only**. After scan completion, findings are automatically exported to the client's Faraday instance for:

- Long-term vulnerability tracking
- Remediation workflow
- Collaboration with client teams
- Professional reports
- Historical trend analysis

See [infra/faraday/README.md](../agentic-bugbounty/infra/faraday/README.md) in the main project for Faraday setup.

## Files

| File | Description |
|------|-------------|
| `app.py` | Main Flask-SocketIO application |
| `event_stream.py` | Event handling and statistics |
| `storage.py` | Persistence layer (SQLite/memory) |
| `Dockerfile` | Container build definition (local) |
| `Dockerfile.fly` | Fly.io production Dockerfile |
| `fly.toml` | Fly.io deployment configuration |
| `deploy.sh` | Fly.io deployment helper script |
| `docker-compose.yml` | Local development setup |
| `docker-compose.prod.yml` | Self-hosted production |

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run with hot reload
FLASK_DEBUG=1 python app.py

# Run tests
pytest tests/
```
