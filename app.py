#!/usr/bin/env python3
"""Agentic Security Dashboard - Real-time Scan Monitoring

Flask-SocketIO dashboard for live scan visibility.
Deployed as Docker container for local dev and production.

Features:
- Real-time WebSocket event streaming
- Token-based authentication
- Live statistics and findings display
- RAG context integration
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, abort
from flask_socketio import SocketIO, emit

# Import event stream from parent project (or standalone version)
try:
    from scan_event_stream import get_event_stream, ScanEvent, EventType
except ImportError:
    # Fallback: create minimal event stream if not available
    from event_stream import get_event_stream, ScanEvent, EventType

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
socketio = SocketIO(
    app,
    cors_allowed_origins=os.getenv('CORS_ORIGINS', '*').split(','),
    async_mode='threading'
)

# Configuration
DASHBOARD_TOKEN = os.getenv('DASHBOARD_TOKEN', 'changeme')
MCP_SERVER_URL = os.getenv('MCP_SERVER_URL', 'http://mcp:8000')
PORT = int(os.getenv('PORT', '5050'))
HOST = os.getenv('HOST', '0.0.0.0')

# HTML template - embedded for single-file simplicity
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Agentic Security - Live Scan Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        :root { 
            --bg: #0b0f17; 
            --card: #101827; 
            --text: #e9eef7; 
            --muted: #a9b4c7; 
            --accent: #7c5cff; 
            --ok: #22c55e; 
            --warn: #f59e0b; 
            --critical: #ef4444; 
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: system-ui, -apple-system, sans-serif; 
            background: var(--bg); 
            color: var(--text); 
            min-height: 100vh; 
            padding: 20px; 
        }
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 1px solid #1f2a3d; 
        }
        .header h1 { font-size: 1.5rem; }
        .status { display: flex; align-items: center; gap: 8px; }
        .status-dot { 
            width: 10px; 
            height: 10px; 
            border-radius: 50%; 
            background: var(--muted); 
        }
        .status-dot.active { 
            background: var(--ok); 
            animation: pulse 2s infinite; 
        }
        @keyframes pulse { 
            0%, 100% { opacity: 1; } 
            50% { opacity: 0.5; } 
        }
        .grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 15px; 
            margin-bottom: 20px; 
        }
        @media (max-width: 900px) { 
            .grid { grid-template-columns: 1fr; } 
        }
        .card { 
            background: var(--card); 
            border-radius: 12px; 
            padding: 15px; 
            border: 1px solid #1f2a3d; 
        }
        .card h3 { 
            color: var(--muted); 
            font-size: 0.85rem; 
            margin-bottom: 10px; 
        }
        .stat-value { 
            font-size: 2rem; 
            font-weight: 700; 
            color: var(--accent); 
        }
        .events { 
            max-height: 400px; 
            overflow-y: auto; 
        }
        .event { 
            padding: 8px 12px; 
            border-bottom: 1px solid #1f2a3d; 
            font-size: 0.85rem; 
            display: flex; 
            gap: 10px; 
        }
        .event:hover { background: rgba(255,255,255,0.02); }
        .event-time { color: var(--muted); min-width: 80px; }
        .event-type { min-width: 140px; font-weight: 600; }
        .event-type.finding_validated { color: var(--critical); }
        .event-type.payload_sent { color: var(--warn); }
        .event-type.endpoint_discovered { color: var(--ok); }
        .event-type.rag_match { color: var(--accent); }
        .event-data { 
            color: var(--muted); 
            overflow: hidden; 
            text-overflow: ellipsis; 
        }
        .findings { 
            display: flex; 
            flex-direction: column; 
            gap: 8px; 
        }
        .finding { 
            padding: 10px; 
            background: rgba(0,0,0,0.2); 
            border-radius: 8px; 
            border-left: 3px solid var(--critical); 
        }
        .finding.high { border-color: var(--warn); }
        .finding.medium { border-color: var(--accent); }
        .finding-title { font-weight: 600; margin-bottom: 4px; }
        .finding-rag { 
            font-size: 0.8rem; 
            color: var(--accent); 
            margin-top: 5px; 
        }
        .auth-form { 
            max-width: 300px; 
            margin: 100px auto; 
            text-align: center; 
        }
        .auth-form input { 
            width: 100%; 
            padding: 12px; 
            margin: 10px 0; 
            border-radius: 8px;
            border: 1px solid #1f2a3d; 
            background: var(--card); 
            color: var(--text); 
        }
        .auth-form button { 
            width: 100%; 
            padding: 12px; 
            border-radius: 8px; 
            border: none;
            background: var(--accent); 
            color: white; 
            font-weight: 600; 
            cursor: pointer; 
        }
    </style>
</head>
<body>
    <div id="auth" style="display: none;">
        <div class="auth-form">
            <h2>Dashboard Access</h2>
            <input type="password" id="token" placeholder="Enter dashboard token">
            <button onclick="authenticate()">Access Dashboard</button>
        </div>
    </div>
    
    <div id="dashboard" style="display: none;">
        <div class="header">
            <h1>🔒 Agentic Security - Live Scan</h1>
            <div class="status">
                <span class="status-dot" id="status-dot"></span>
                <span id="status-text">Connecting...</span>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>SCAN PROGRESS</h3>
                <div class="stat-value" id="scan-target">-</div>
                <div style="margin-top: 10px; color: var(--muted);">
                    <span id="scan-duration">0:00</span> elapsed
                </div>
            </div>
            <div class="card">
                <h3>STATISTICS</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    <div><span id="stat-requests">0</span> requests</div>
                    <div><span id="stat-endpoints">0</span> endpoints</div>
                    <div><span id="stat-payloads">0</span> payloads</div>
                    <div><span id="stat-findings" style="color: var(--critical);">0</span> findings</div>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>LIVE EVENT STREAM</h3>
                <div class="events" id="events"></div>
            </div>
            <div class="card">
                <h3>FINDINGS (with RAG Context)</h3>
                <div class="findings" id="findings"></div>
            </div>
        </div>
    </div>

    <script>
        let socket;
        let authenticated = false;
        const token = localStorage.getItem('dashboard_token');
        
        if (token) { tryConnect(token); } 
        else { document.getElementById('auth').style.display = 'block'; }
        
        function authenticate() {
            const token = document.getElementById('token').value;
            tryConnect(token);
        }
        
        function tryConnect(token) {
            socket = io({ 
                auth: { token: token },
                transports: ['websocket', 'polling']
            });
            
            socket.on('connect', () => {
                authenticated = true;
                localStorage.setItem('dashboard_token', token);
                document.getElementById('auth').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                document.getElementById('status-dot').classList.add('active');
                document.getElementById('status-text').textContent = 'Connected';
            });
            
            socket.on('connect_error', (err) => {
                localStorage.removeItem('dashboard_token');
                document.getElementById('auth').style.display = 'block';
                document.getElementById('dashboard').style.display = 'none';
                document.getElementById('status-text').textContent = 'Connection failed';
            });
            
            socket.on('scan_event', (event) => { handleEvent(event); });
            socket.on('stats_update', (stats) => { updateStats(stats); });
        }
        
        function handleEvent(event) {
            // Add to event stream
            const events = document.getElementById('events');
            const time = new Date(event.timestamp).toLocaleTimeString();
            const div = document.createElement('div');
            div.className = 'event';
            div.innerHTML = `
                <span class="event-time">${time}</span>
                <span class="event-type ${event.event_type}">${event.event_type}</span>
                <span class="event-data">${JSON.stringify(event.data || {}).slice(0, 80)}...</span>
            `;
            events.insertBefore(div, events.firstChild);
            if (events.children.length > 50) events.removeChild(events.lastChild);
            
            // Handle findings
            if (event.event_type === 'finding_validated' || event.event_type === 'finding_candidate') {
                addFinding(event.data || {});
            }
            
            // Update target
            if (event.event_type === 'scan_start') {
                document.getElementById('scan-target').textContent = event.data?.target || '-';
            }
        }
        
        function addFinding(data) {
            const findings = document.getElementById('findings');
            const div = document.createElement('div');
            div.className = `finding ${data.severity || 'medium'}`;
            div.innerHTML = `
                <div class="finding-title">${data.title || 'Finding'}</div>
                <div style="color: var(--muted); font-size: 0.85rem;">Severity: ${data.severity || 'unknown'}</div>
                ${data.rag_context ? `<div class="finding-rag">📚 ${data.rag_context}</div>` : ''}
            `;
            findings.insertBefore(div, findings.firstChild);
        }
        
        function updateStats(stats) {
            document.getElementById('stat-requests').textContent = stats.stats?.requests_sent || 0;
            document.getElementById('stat-endpoints').textContent = stats.stats?.endpoints_found || 0;
            document.getElementById('stat-payloads').textContent = stats.stats?.payloads_tested || 0;
            document.getElementById('stat-findings').textContent = stats.stats?.findings_discovered || 0;
            if (stats.duration_seconds) {
                const mins = Math.floor(stats.duration_seconds / 60);
                const secs = Math.floor(stats.duration_seconds % 60);
                document.getElementById('scan-duration').textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """Serve the dashboard HTML."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'dashboard'})


@app.route('/api/stats')
def get_stats():
    """Get current scan statistics."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    return jsonify(get_event_stream().get_stats())


@app.route('/api/events')
def get_events():
    """Get recent events."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    count = request.args.get('count', 50, type=int)
    return jsonify(get_event_stream().get_recent_events(count))


@app.route('/api/event', methods=['POST'])
def post_event():
    """Receive events from external processes and broadcast to WebSocket clients."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    data = request.get_json()
    if not data:
        abort(400, 'JSON body required')
    
    event_type_str = data.get('event_type', 'info')
    payload = data.get('payload', {})
    scan_id = data.get('scan_id')
    
    # Convert string to EventType enum if possible
    event_type = None
    for et in EventType:
        if et.value == event_type_str or et.name.lower() == event_type_str.lower():
            event_type = et
            break
    if event_type is None:
        event_type = EventType.SCAN_PROGRESS  # Default fallback
    
    # Create and emit event
    stream = get_event_stream()
    event = stream.emit(event_type, payload)
    
    # Broadcast to all connected WebSocket clients
    socketio.emit('scan_event', event.to_dict())
    socketio.emit('stats_update', stream.get_stats())
    
    return jsonify({'status': 'ok', 'event_id': event.event_id})


@socketio.on('connect')
def handle_connect(auth=None):
    """Handle WebSocket connection with token auth."""
    token = request.args.get('token') or (auth.get('token') if auth else None)
    if token != DASHBOARD_TOKEN:
        return False  # Reject connection
    
    # Send current stats on connect
    emit('stats_update', get_event_stream().get_stats())
    
    # Send recent events
    for event in get_event_stream().get_recent_events(20):
        emit('scan_event', event.to_dict())


def broadcast_event(event: ScanEvent):
    """Broadcast an event to all connected clients."""
    socketio.emit('scan_event', event.to_dict())
    socketio.emit('stats_update', get_event_stream().get_stats())


def setup_event_broadcasting():
    """Connect the event stream to WebSocket broadcasting."""
    stream = get_event_stream()
    stream.on_event(broadcast_event)


if __name__ == '__main__':
    print(f"🔒 Dashboard starting on http://{HOST}:{PORT}")
    print(f"   Token: {'*' * len(DASHBOARD_TOKEN)} (set DASHBOARD_TOKEN env var)")
    print(f"   MCP Server: {MCP_SERVER_URL}")
    
    setup_event_broadcasting()
    socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)

