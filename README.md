# Agentic Security Dashboard

Real-time scan monitoring dashboard for Agentic Security Partners. Built with Flask-SocketIO for live WebSocket event streaming.

## Features

- 🔴 **Real-time Event Streaming** - Live WebSocket updates for scan progress
- 📊 **Live Statistics** - Requests, endpoints, payloads, findings
- 🔍 **Findings Display** - Real-time vulnerability discoveries with RAG context
- 🔐 **Token Authentication** - Simple token-based access control
- 🐳 **Docker Support** - Full containerization for dev and production

## Quick Start

### Local Development

1. **Clone and setup:**
```bash
git clone <repo-url>
cd agentic-security-dashboard
cp .env.example .env
# Edit .env with your DASHBOARD_TOKEN
```

2. **Run with Docker Compose:**
```bash
docker compose up
```

3. **Access dashboard:**
- Open http://localhost:5050
- Enter your `DASHBOARD_TOKEN` when prompted

### Production Deployment

1. **Build production image:**
```bash
docker build -t agentic-dashboard:latest .
```

2. **Deploy with docker-compose:**
```bash
# Set environment variables
export DASHBOARD_TOKEN="your-production-token"
export MCP_SERVER_URL="http://mcp:8000"

# Deploy
docker compose -f docker-compose.prod.yml up -d
```

3. **Or integrate into main docker-compose.prod.yml:**
```yaml
services:
  dashboard:
    build:
      context: ./agentic-security-dashboard
      dockerfile: Dockerfile
    environment:
      - DASHBOARD_TOKEN=${DASHBOARD_TOKEN}
      - MCP_SERVER_URL=http://mcp:8000
    ports:
      - "127.0.0.1:5050:5050"
    networks:
      - agentic-prod
```

## Architecture

```
┌─────────────────────────────────────────┐
│         Client Browser                   │
│    (WebSocket Connection)                │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      Dashboard (Flask-SocketIO)         │
│      Port: 5050                          │
│      - WebSocket server                  │
│      - Event broadcasting                │
│      - Token authentication              │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      MCP Server (FastAPI)               │
│      Port: 8000                          │
│      - Scan orchestration                │
│      - Event emission                    │
└─────────────────────────────────────────┘
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DASHBOARD_TOKEN` | Authentication token (required) | `changeme` |
| `MCP_SERVER_URL` | MCP server URL | `http://mcp:8000` |
| `PORT` | Dashboard port | `5050` |
| `HOST` | Bind address | `0.0.0.0` |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `SECRET_KEY` | Flask secret key | Auto-generated |

## API Endpoints

### WebSocket
- **Connection:** `ws://localhost:5050`
- **Auth:** Token via `auth.token` in connection
- **Events:**
  - `scan_event` - Real-time scan events
  - `stats_update` - Statistics updates

### HTTP REST
- `GET /` - Dashboard HTML
- `GET /health` - Health check
- `GET /api/stats` - Get statistics (requires `Authorization: Bearer <token>`)
- `GET /api/events` - Get recent events (requires `Authorization: Bearer <token>`)
- `POST /api/event` - Post new event (requires `Authorization: Bearer <token>`)

## Event Types

The dashboard supports these event types:

- `scan_start` - Scan initiated
- `scan_progress` - Scan progress update
- `scan_complete` - Scan finished
- `scan_error` - Scan error
- `endpoint_discovered` - New endpoint found
- `tech_fingerprint` - Technology detected
- `payload_sent` - Test payload sent
- `finding_candidate` - Potential vulnerability
- `finding_validated` - Confirmed vulnerability
- `rag_match` - RAG context match

## Development

### Local Development (without Docker)

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
export DASHBOARD_TOKEN=dev-token
python app.py
```

### Building Docker Image

```bash
# Build
docker build -t agentic-dashboard:latest .

# Test locally
docker run -p 5050:5050 \
  -e DASHBOARD_TOKEN=test-token \
  agentic-dashboard:latest
```

### Publishing Production Image

```bash
# Tag for registry
docker tag agentic-dashboard:latest \
  registry.example.com/agentic-dashboard:v1.0.0

# Push
docker push registry.example.com/agentic-dashboard:v1.0.0
```

## Integration with Main Project

To integrate this dashboard into the main `agentic-bugbounty` project:

1. **Add to docker-compose.prod.yml:**
```yaml
services:
  dashboard:
    build:
      context: ../agentic-security-dashboard
      dockerfile: Dockerfile
    environment:
      - DASHBOARD_TOKEN=${DASHBOARD_TOKEN}
      - MCP_SERVER_URL=http://mcp:8000
    ports:
      - "127.0.0.1:5050:5050"
    networks:
      - agentic-prod
```

2. **Update MCP server to emit events:**
The MCP server should POST events to `http://dashboard:5050/api/event` with the dashboard token.

## Security Notes

- **Token Authentication:** Always use strong, random tokens in production
- **Network Binding:** Production binds to `127.0.0.1` - use nginx reverse proxy
- **CORS:** Configure `CORS_ORIGINS` to restrict origins in production
- **HTTPS:** Use nginx/cloudflare for HTTPS termination

## Troubleshooting

### Dashboard not connecting
- Check `DASHBOARD_TOKEN` matches between client and server
- Verify WebSocket connection (check browser console)
- Ensure CORS is configured correctly

### Events not appearing
- Verify MCP server is posting to `/api/event` endpoint
- Check dashboard logs: `docker logs dashboard-prod`
- Verify network connectivity between services

### High memory usage
- Adjust `max_events` in `event_stream.py` (default: 100)
- Events are kept in memory only (no persistence)

## License

MIT License © 2025 Agentic Security Partners

