#!/usr/bin/env python3
"""Agentic Security Dashboard - Real-time Scan Monitoring

Flask-SocketIO dashboard for live scan visibility.
Deployed as Docker container for local dev and production.

This is a lightweight streaming-only dashboard. For full vulnerability
management, findings are pushed to per-client Faraday instances.

Features:
- Real-time WebSocket event streaming
- Token-based authentication
- Live statistics display
- Scan progress and phase tracking
- Tech stack fingerprint display
"""

import os
import json
import signal
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, abort
from flask_socketio import SocketIO, emit

# Import event stream
try:
    from scan_event_stream import get_event_stream, ScanEvent, EventType
except ImportError:
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
PORT = int(os.getenv('PORT', '5050'))
HOST = os.getenv('HOST', '0.0.0.0')
KILL_SIGNAL_DIR = Path(os.getenv('KILL_SIGNAL_DIR', '/tmp/agentic-scan-signals'))

# Ensure signal directory exists
KILL_SIGNAL_DIR.mkdir(parents=True, exist_ok=True)

# Active scans tracking (org_id -> scan_info)
active_scans = {}

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
        .grid-3 {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        @media (max-width: 1200px) {
            .grid-3 { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 900px) { 
            .grid { grid-template-columns: 1fr; } 
            .grid-3 { grid-template-columns: 1fr; }
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
        .progress-bar {
            height: 8px;
            background: #1f2a3d;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--ok));
            transition: width 0.3s ease;
        }
        .phase-badge {
            display: inline-block;
            padding: 4px 12px;
            background: rgba(124, 92, 255, 0.2);
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--accent);
            margin-top: 8px;
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
        .event-type.finding_candidate { color: var(--warn); }
        .event-type.payload_sent { color: var(--warn); }
        .event-type.endpoint_discovered { color: var(--ok); }
        .event-type.tech_fingerprint { color: #3b82f6; }
        .event-type.rag_match { color: var(--accent); }
        .event-type.phase_start { color: #10b981; }
        .event-type.scan_start { color: #22c55e; }
        .event-type.scan_complete { color: #22c55e; }
        .event-data { 
            color: var(--muted); 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap;
        }
        .findings { 
            display: flex; 
            flex-direction: column; 
            gap: 8px;
            max-height: 400px;
            overflow-y: auto;
        }
        .finding { 
            padding: 10px; 
            background: rgba(0,0,0,0.2); 
            border-radius: 8px; 
            border-left: 3px solid var(--critical); 
        }
        .finding.high { border-color: var(--warn); }
        .finding.medium { border-color: var(--accent); }
        .finding.low { border-color: var(--muted); }
        .finding-title { font-weight: 600; margin-bottom: 4px; }
        .finding-rag { 
            font-size: 0.8rem; 
            color: var(--accent); 
            margin-top: 5px; 
        }
        .tech-stack {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .tech-tag {
            display: inline-block;
            padding: 4px 10px;
            background: rgba(59, 130, 246, 0.2);
            border-radius: 4px;
            font-size: 0.75rem;
            color: #3b82f6;
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
        .faraday-link {
            margin-top: 15px;
            padding: 10px;
            background: rgba(34, 197, 94, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        .faraday-link a {
            color: var(--ok);
            text-decoration: none;
        }
        .faraday-link a:hover {
            text-decoration: underline;
        }
        .kill-btn {
            background: var(--critical);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .kill-btn:hover {
            background: #dc2626;
            transform: scale(1.02);
        }
        .kill-btn:disabled {
            background: var(--muted);
            cursor: not-allowed;
            transform: none;
        }
        .kill-btn.killing {
            background: var(--warn);
            animation: pulse 1s infinite;
        }
        .kill-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .kill-modal.active {
            display: flex;
        }
        .kill-modal-content {
            background: var(--card);
            border-radius: 12px;
            padding: 30px;
            max-width: 400px;
            text-align: center;
            border: 1px solid var(--critical);
        }
        .kill-modal h2 {
            color: var(--critical);
            margin-bottom: 15px;
        }
        .kill-modal p {
            color: var(--muted);
            margin-bottom: 20px;
        }
        .kill-modal-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
        }
        .kill-modal-buttons button {
            padding: 10px 25px;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            cursor: pointer;
        }
        .kill-modal-buttons .cancel {
            background: var(--muted);
            color: var(--bg);
        }
        .kill-modal-buttons .confirm {
            background: var(--critical);
            color: white;
        }
    </style>
</head>
<body>
    <div id="auth">
        <div class="auth-form">
            <h2>🔒 Dashboard Access</h2>
            <input type="password" id="token" placeholder="Enter dashboard token" onkeypress="if(event.key==='Enter')authenticate()">
            <button id="auth-btn" onclick="authenticate()">Access Dashboard</button>
            <p id="auth-error" style="color: var(--critical); margin-top: 10px; display: none;"></p>
        </div>
    </div>
    
    <div id="dashboard" style="display: none;">
        <div class="header">
            <h1>🔒 Agentic Security - Live Scan</h1>
            <div style="display: flex; align-items: center; gap: 20px;">
                <button class="kill-btn" id="kill-btn" onclick="showKillModal()" disabled>
                    ⛔ Emergency Stop
                </button>
                <div class="status">
                    <span class="status-dot" id="status-dot"></span>
                    <span id="status-text">Connecting...</span>
                </div>
            </div>
        </div>
        
        <!-- Kill Confirmation Modal -->
        <div class="kill-modal" id="kill-modal">
            <div class="kill-modal-content">
                <h2>⚠️ Stop Scan?</h2>
                <p>This will immediately stop all scanning activity for your organization. The scan cannot be resumed - you'll need to start a new scan.</p>
                <div class="kill-modal-buttons">
                    <button class="cancel" onclick="hideKillModal()">Cancel</button>
                    <button class="confirm" onclick="confirmKill()">Stop Scan</button>
                </div>
            </div>
        </div>
        
        <div class="grid-3">
            <div class="card">
                <h3>SCAN PROGRESS</h3>
                <div class="stat-value" id="scan-target">-</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill" style="width: 0%"></div>
                </div>
                <div style="margin-top: 10px; color: var(--muted); display: flex; justify-content: space-between;">
                    <span><span id="scan-duration">0:00</span> elapsed</span>
                    <span id="progress-pct">0%</span>
                </div>
                <div class="phase-badge" id="phase-badge" style="display: none;">RECON</div>
            </div>
            <div class="card">
                <h3>STATISTICS</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    <div><span id="stat-requests" style="font-weight: 700;">0</span> requests</div>
                    <div><span id="stat-endpoints" style="font-weight: 700;">0</span> endpoints</div>
                    <div><span id="stat-payloads" style="font-weight: 700;">0</span> payloads</div>
                    <div><span id="stat-findings" style="color: var(--critical); font-weight: 700;">0</span> findings</div>
                </div>
                <div id="eta-display" style="margin-top: 10px; color: var(--muted); font-size: 0.85rem;"></div>
            </div>
            <div class="card">
                <h3>TECH STACK DETECTED</h3>
                <div class="tech-stack" id="tech-stack">
                    <span style="color: var(--muted);">Detecting...</span>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>LIVE EVENT STREAM</h3>
                <div class="events" id="events"></div>
            </div>
            <div class="card">
                <h3>LIVE FINDINGS</h3>
                <div class="findings" id="findings">
                    <div style="color: var(--muted); padding: 20px; text-align: center;">
                        Waiting for findings...
                    </div>
                </div>
                <div class="faraday-link" id="faraday-link" style="display: none;">
                    📊 Full results available in <a href="#" id="faraday-url" target="_blank">Faraday Dashboard</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        let socket;
        let authenticated = false;
        let findingsCount = 0;
        const savedToken = localStorage.getItem('dashboard_token');
        
        // If we have a saved token, try to connect automatically
        if (savedToken) { 
            document.getElementById('auth').style.display = 'none';
            tryConnect(savedToken); 
        }
        // Otherwise auth form is already visible (no display:none on it)
        
        function authenticate() {
            const token = document.getElementById('token').value;
            if (!token) {
                showAuthError('Please enter a token');
                return;
            }
            const btn = document.getElementById('auth-btn');
            btn.textContent = 'Connecting...';
            btn.disabled = true;
            hideAuthError();
            tryConnect(token);
        }
        
        function showAuthError(msg) {
            const errEl = document.getElementById('auth-error');
            errEl.textContent = msg;
            errEl.style.display = 'block';
        }
        
        function hideAuthError() {
            document.getElementById('auth-error').style.display = 'none';
        }
        
        function resetAuthButton() {
            const btn = document.getElementById('auth-btn');
            btn.textContent = 'Access Dashboard';
            btn.disabled = false;
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
                resetAuthButton();
            });
            
            socket.on('connect_error', (err) => {
                localStorage.removeItem('dashboard_token');
                document.getElementById('auth').style.display = 'block';
                document.getElementById('dashboard').style.display = 'none';
                document.getElementById('status-text').textContent = 'Connection failed';
                showAuthError('Invalid token or connection failed. Try again.');
                resetAuthButton();
            });
            
            socket.on('disconnect', () => {
                document.getElementById('status-dot').classList.remove('active');
                document.getElementById('status-text').textContent = 'Disconnected';
            });
            
            socket.on('scan_event', (event) => { handleEvent(event); });
            socket.on('stats_update', (stats) => { updateStats(stats); });
            
            // Kill switch socket events
            socket.on('scan_registered', (data) => {
                currentOrgId = data.org_id;
                scanIsRunning = true;
                const killBtn = document.getElementById('kill-btn');
                killBtn.disabled = false;
                killBtn.textContent = '⛔ Emergency Stop';
            });
            
            socket.on('scan_killed', (data) => {
                scanIsRunning = false;
                const killBtn = document.getElementById('kill-btn');
                killBtn.disabled = true;
                killBtn.textContent = '✅ Scan Stopped';
                killBtn.classList.remove('killing');
            });
            
            socket.on('active_scans', (scans) => {
                const hasActiveScans = Object.values(scans).some(s => s.status === 'running');
                if (hasActiveScans) {
                    const firstOrg = Object.keys(scans)[0];
                    currentOrgId = firstOrg;
                    scanIsRunning = true;
                    document.getElementById('kill-btn').disabled = false;
                }
            });
        }
        
        function addFinding(data) {
            const findings = document.getElementById('findings');
            
            // Remove placeholder on first finding
            if (findingsCount === 0) {
                findings.innerHTML = '';
            }
            findingsCount++;
            
            const div = document.createElement('div');
            const severity = (data.severity || 'medium').toLowerCase();
            div.className = `finding ${severity}`;
            div.innerHTML = `
                <div class="finding-title">${escapeHtml(data.title || 'Finding')}</div>
                <div style="color: var(--muted); font-size: 0.85rem;">
                    Severity: ${severity} ${data.cwe ? '| ' + data.cwe : ''}
                </div>
                ${data.rag_context ? `<div class="finding-rag">📚 Similar: ${escapeHtml(data.rag_context)}</div>` : ''}
            `;
            findings.insertBefore(div, findings.firstChild);
            
            // Limit displayed findings
            if (findings.children.length > 20) {
                findings.removeChild(findings.lastChild);
            }
        }
        
        function addTechTag(tech) {
            if (!tech) return;
            const container = document.getElementById('tech-stack');
            
            // Clear placeholder
            if (container.querySelector('span[style]')) {
                container.innerHTML = '';
            }
            
            // Check if already exists
            if ([...container.children].some(el => el.textContent === tech)) return;
            
            const tag = document.createElement('span');
            tag.className = 'tech-tag';
            tag.textContent = tech;
            container.appendChild(tag);
        }
        
        function updateStats(stats) {
            document.getElementById('stat-requests').textContent = stats.stats?.requests_sent || 0;
            document.getElementById('stat-endpoints').textContent = stats.stats?.endpoints_found || 0;
            document.getElementById('stat-payloads').textContent = stats.stats?.payloads_tested || 0;
            document.getElementById('stat-findings').textContent = stats.stats?.findings_discovered || 0;
            
            // Duration
            if (stats.duration_seconds) {
                const mins = Math.floor(stats.duration_seconds / 60);
                const secs = Math.floor(stats.duration_seconds % 60);
                document.getElementById('scan-duration').textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
            }
            
            // Progress
            const pct = stats.progress_percentage || 0;
            document.getElementById('progress-fill').style.width = `${pct}%`;
            document.getElementById('progress-pct').textContent = `${Math.round(pct)}%`;
            
            // ETA
            if (stats.eta_seconds && stats.eta_seconds > 0) {
                const etaMins = Math.floor(stats.eta_seconds / 60);
                const etaSecs = Math.floor(stats.eta_seconds % 60);
                document.getElementById('eta-display').textContent = `ETA: ~${etaMins}:${etaSecs.toString().padStart(2, '0')}`;
            }
            
            // Phase
            if (stats.current_phase) {
                const badge = document.getElementById('phase-badge');
                badge.textContent = stats.current_phase.toUpperCase();
                badge.style.display = 'inline-block';
            }
            
            // Tech stack from stats
            if (stats.tech_stack) {
                for (const tech of Object.keys(stats.tech_stack)) {
                    addTechTag(tech);
                }
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Kill switch functions
        let currentOrgId = 'default';
        let scanIsRunning = false;
        
        function showKillModal() {
            document.getElementById('kill-modal').classList.add('active');
        }
        
        function hideKillModal() {
            document.getElementById('kill-modal').classList.remove('active');
        }
        
        function confirmKill() {
            const killBtn = document.getElementById('kill-btn');
            killBtn.classList.add('killing');
            killBtn.textContent = '⏳ Stopping...';
            killBtn.disabled = true;
            hideKillModal();
            
            const token = localStorage.getItem('dashboard_token');
            fetch('/api/scan/kill', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    org_id: currentOrgId,
                    reason: 'User requested emergency stop from dashboard'
                })
            })
            .then(res => res.json())
            .then(data => {
                killBtn.classList.remove('killing');
                killBtn.textContent = '✅ Stopped';
                addEvent({
                    event_type: 'scan_killed',
                    timestamp: new Date().toISOString(),
                    data: { message: 'Scan stopped by user', org_id: currentOrgId }
                });
            })
            .catch(err => {
                killBtn.classList.remove('killing');
                killBtn.textContent = '⛔ Emergency Stop';
                killBtn.disabled = false;
                console.error('Kill failed:', err);
            });
        }
        
        function addEvent(event) {
            const events = document.getElementById('events');
            const time = new Date(event.timestamp).toLocaleTimeString();
            const div = document.createElement('div');
            div.className = 'event';
            
            const dataStr = JSON.stringify(event.data || {});
            const truncatedData = dataStr.length > 80 ? dataStr.slice(0, 80) + '...' : dataStr;
            
            div.innerHTML = `
                <span class="event-time">${time}</span>
                <span class="event-type ${event.event_type}">${event.event_type.replace(/_/g, ' ')}</span>
                <span class="event-data">${truncatedData}</span>
            `;
            events.insertBefore(div, events.firstChild);
        }
        
        // Main event handler
        function handleEvent(event) {
            // Enable kill button on scan start
            if (event.event_type === 'scan_start') {
                scanIsRunning = true;
                const killBtn = document.getElementById('kill-btn');
                killBtn.disabled = false;
                killBtn.textContent = '⛔ Emergency Stop';
                killBtn.classList.remove('killing');
            }
            
            // Disable on scan complete
            if (event.event_type === 'scan_complete') {
                scanIsRunning = false;
                const killBtn = document.getElementById('kill-btn');
                killBtn.disabled = true;
                if (event.data?.status === 'killed') {
                    killBtn.textContent = '✅ Scan Stopped';
                } else {
                    killBtn.textContent = '✓ Scan Complete';
                }
            }
            
            // Original event handling...
            addEvent(event);
            
            // Handle findings
            if (event.event_type === 'finding_validated' || event.event_type === 'finding_candidate') {
                addFinding(event.data || {});
            }
            
            // Update target on scan start
            if (event.event_type === 'scan_start') {
                document.getElementById('scan-target').textContent = event.data?.target || '-';
                currentOrgId = event.data?.org_id || 'default';
                findingsCount = 0;
                document.getElementById('findings').innerHTML = '<div style="color: var(--muted); padding: 20px; text-align: center;">Waiting for findings...</div>';
            }
            
            // Show phase
            if (event.event_type === 'phase_start') {
                const badge = document.getElementById('phase-badge');
                badge.textContent = (event.data?.phase || 'UNKNOWN').toUpperCase();
                badge.style.display = 'inline-block';
            }
            
            // Update tech stack
            if (event.event_type === 'tech_fingerprint') {
                addTechTag(event.data?.technology || event.data?.tech);
            }
            
            // Show Faraday link on scan complete
            if (event.event_type === 'scan_complete' && event.data?.faraday_url) {
                const linkDiv = document.getElementById('faraday-link');
                const linkUrl = document.getElementById('faraday-url');
                linkUrl.href = event.data.faraday_url;
                linkDiv.style.display = 'block';
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
    return jsonify({'status': 'healthy', 'service': 'live-dashboard'})


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
    """Receive events from external processes and broadcast to WebSocket clients.
    
    This endpoint is called by the agentic_runner to push scan events
    to connected dashboard clients in real-time.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    data = request.get_json()
    if not data:
        abort(400, 'JSON body required')
    
    event_type_str = data.get('event_type', 'info')
    payload = data.get('payload', {})
    
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


@app.route('/api/scan/register', methods=['POST'])
def register_scan():
    """Register an active scan for kill switch tracking.
    
    Called by agentic_runner when a scan starts.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    data = request.get_json()
    if not data:
        abort(400, 'JSON body required')
    
    org_id = data.get('org_id', 'default')
    scan_id = data.get('scan_id', f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    pid = data.get('pid')
    target = data.get('target', 'Unknown')
    
    active_scans[org_id] = {
        'scan_id': scan_id,
        'pid': pid,
        'target': target,
        'started_at': datetime.now().isoformat(),
        'status': 'running'
    }
    
    # Broadcast scan start
    socketio.emit('scan_registered', {'org_id': org_id, 'scan': active_scans[org_id]})
    
    return jsonify({'status': 'ok', 'scan_id': scan_id, 'org_id': org_id})


@app.route('/api/scan/kill', methods=['POST'])
def kill_scan():
    """Kill switch - stop a running scan for an organization.
    
    Creates a kill signal file that the agentic_runner monitors.
    The scanner will gracefully stop when it detects the signal.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    data = request.get_json() or {}
    org_id = data.get('org_id', 'default')
    reason = data.get('reason', 'User requested stop')
    
    # Create kill signal file
    kill_file = KILL_SIGNAL_DIR / f"kill_{org_id}.signal"
    kill_data = {
        'org_id': org_id,
        'reason': reason,
        'killed_at': datetime.now().isoformat(),
        'killed_by': 'dashboard_user'
    }
    kill_file.write_text(json.dumps(kill_data))
    
    # Update active scan status
    if org_id in active_scans:
        active_scans[org_id]['status'] = 'killing'
        active_scans[org_id]['kill_reason'] = reason
    
    # Broadcast kill event
    socketio.emit('scan_killed', {
        'org_id': org_id,
        'reason': reason,
        'message': f'Kill signal sent for {org_id}'
    })
    
    # Also emit as scan event for the event stream
    stream = get_event_stream()
    event = stream.emit(EventType.SCAN_COMPLETE, {
        'status': 'killed',
        'reason': reason,
        'org_id': org_id
    })
    socketio.emit('scan_event', event.to_dict())
    
    return jsonify({
        'status': 'ok',
        'message': f'Kill signal sent for organization {org_id}',
        'kill_file': str(kill_file)
    })


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get status of active scans."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    org_id = request.args.get('org_id')
    
    if org_id:
        scan = active_scans.get(org_id)
        if not scan:
            return jsonify({'status': 'not_found', 'org_id': org_id})
        
        # Check for kill signal
        kill_file = KILL_SIGNAL_DIR / f"kill_{org_id}.signal"
        if kill_file.exists():
            scan['kill_pending'] = True
        
        return jsonify({'status': 'ok', 'scan': scan})
    
    return jsonify({'status': 'ok', 'scans': active_scans})


@app.route('/api/scan/clear-kill', methods=['POST'])
def clear_kill_signal():
    """Clear a kill signal (for restarting scans)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    data = request.get_json() or {}
    org_id = data.get('org_id', 'default')
    
    kill_file = KILL_SIGNAL_DIR / f"kill_{org_id}.signal"
    if kill_file.exists():
        kill_file.unlink()
        return jsonify({'status': 'ok', 'message': f'Kill signal cleared for {org_id}'})
    
    return jsonify({'status': 'ok', 'message': 'No kill signal to clear'})


@socketio.on('connect')
def handle_connect(auth=None):
    """Handle WebSocket connection with token auth."""
    # Debug: log what we receive
    print(f"[DEBUG] Connect attempt - auth={auth}, args={dict(request.args)}", flush=True)
    
    token = request.args.get('token') or (auth.get('token') if auth else None)
    print(f"[DEBUG] Extracted token={token!r}, expected={DASHBOARD_TOKEN!r}", flush=True)
    
    if token != DASHBOARD_TOKEN:
        print(f"[DEBUG] Token mismatch - rejecting connection", flush=True)
        return False  # Reject connection
    
    print(f"[DEBUG] Token valid - accepting connection", flush=True)
    
    try:
        # Send current stats on connect
        emit('stats_update', get_event_stream().get_stats())
        
        # Send active scans
        emit('active_scans', active_scans)
        
        # Send recent events
        for event in get_event_stream().get_recent_events(20):
            emit('scan_event', event.to_dict())
    except Exception as e:
        print(f"[DEBUG] Error in connect handler: {e}", flush=True)


def broadcast_event(event: ScanEvent):
    """Broadcast an event to all connected clients."""
    socketio.emit('scan_event', event.to_dict())
    socketio.emit('stats_update', get_event_stream().get_stats())


def setup_event_broadcasting():
    """Connect the event stream to WebSocket broadcasting."""
    stream = get_event_stream()
    stream.on_event(broadcast_event)


if __name__ == '__main__':
    print(f"🔒 Live Dashboard starting on http://{HOST}:{PORT}")
    print(f"   Token: {'*' * len(DASHBOARD_TOKEN)} (set DASHBOARD_TOKEN env var)")
    print(f"   Note: Full vulnerability management available in Faraday")
    
    setup_event_broadcasting()
    socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)
