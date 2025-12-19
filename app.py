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
- Persistent storage (SQLite for Fly.io, in-memory for dev)
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

# Import storage backend
try:
    from storage import get_storage
except ImportError:
    get_storage = None

app = Flask(__name__)
STARTED_AT = datetime.utcnow().isoformat()
APP_VERSION = os.getenv('APP_VERSION', os.getenv('FLY_IMAGE_REF', 'unknown'))

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

# Initialize storage backend
storage = None
if get_storage:
    try:
        storage = get_storage()
        print(f"[Dashboard] Storage backend initialized: {type(storage).__name__}")
    except Exception as e:
        print(f"[Dashboard] Storage init failed, using in-memory: {e}")

# Active scans tracking (org_id -> scan_info)
# Falls back to in-memory if storage not available
active_scans = {}
if storage:
    try:
        active_scans = storage.get_active_scans()
        print(f"[Dashboard] Loaded {len(active_scans)} active scans from storage")
    except Exception as e:
        print(f"[Dashboard] Failed to load scans from storage: {e}")

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
        /* Executive Summary Styles */
        .exec-summary {
            background: linear-gradient(135deg, rgba(124, 92, 255, 0.1), rgba(34, 197, 94, 0.05));
            border: 1px solid rgba(124, 92, 255, 0.3);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .exec-summary h2 {
            font-size: 1.1rem;
            color: var(--muted);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .exec-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        @media (max-width: 1000px) {
            .exec-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 600px) {
            .exec-grid { grid-template-columns: 1fr; }
        }
        .exec-card {
            text-align: center;
            padding: 16px;
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
        }
        .exec-card .label {
            font-size: 0.8rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .exec-card .value {
            font-size: 2.5rem;
            font-weight: 800;
        }
        .exec-card .subtext {
            font-size: 0.85rem;
            color: var(--muted);
            margin-top: 4px;
        }
        .exec-card.risk-none .value { color: var(--ok); }
        .exec-card.risk-low .value { color: var(--accent); }
        .exec-card.risk-medium .value { color: var(--warn); }
        .exec-card.risk-high .value { color: var(--critical); }
        .exec-progress {
            margin-top: 20px;
        }
        .exec-progress-bar {
            height: 12px;
            background: rgba(255,255,255,0.1);
            border-radius: 6px;
            overflow: hidden;
        }
        .exec-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--ok));
            transition: width 0.5s ease;
            border-radius: 6px;
        }
        .exec-progress-text {
            display: flex;
            justify-content: space-between;
            margin-top: 8px;
            font-size: 0.85rem;
            color: var(--muted);
        }
        /* Toggle Button */
        .view-toggle {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .toggle-btn {
            background: var(--card);
            border: 1px solid #1f2a3d;
            color: var(--muted);
            padding: 10px 24px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .toggle-btn:first-child { 
            border-radius: 8px 0 0 8px; 
        }
        .toggle-btn:last-child { 
            border-radius: 0 8px 8px 0; 
        }
        .toggle-btn.active {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }
        .toggle-btn:hover:not(.active) {
            background: rgba(124, 92, 255, 0.1);
        }
        .advanced-view {
            display: none;
        }
        .advanced-view.visible {
            display: block;
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
        /* Endpoints List Styles */
        .endpoints-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .endpoint-item {
            padding: 10px 12px;
            border-bottom: 1px solid #1f2a3d;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: background 0.2s ease;
        }
        .endpoint-item:hover {
            background: rgba(124, 92, 255, 0.1);
        }
        .endpoint-item .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .endpoint-item .status-indicator.discovered { background: var(--muted); }
        .endpoint-item .status-indicator.tested { background: var(--accent); }
        .endpoint-item .status-indicator.vulnerable { background: var(--critical); animation: pulse 1.5s infinite; }
        .endpoint-item .status-indicator.clean { background: var(--ok); }
        .endpoint-item .endpoint-url {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 0.85rem;
        }
        .endpoint-item .endpoint-method {
            font-size: 0.7rem;
            padding: 2px 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            color: var(--muted);
        }
        .endpoint-item .findings-badge {
            font-size: 0.75rem;
            padding: 2px 8px;
            background: var(--critical);
            border-radius: 10px;
            color: white;
        }
        /* Endpoint Modal Styles */
        .endpoint-modal {
            position: fixed;
            top: 0;
            right: -500px;
            width: 500px;
            height: 100vh;
            background: var(--card);
            border-left: 1px solid #1f2a3d;
            z-index: 1000;
            transition: right 0.3s ease;
            display: flex;
            flex-direction: column;
        }
        .endpoint-modal.active {
            right: 0;
        }
        .endpoint-modal-header {
            padding: 20px;
            border-bottom: 1px solid #1f2a3d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .endpoint-modal-header h2 {
            font-size: 1.1rem;
            margin: 0;
        }
        .close-btn {
            background: none;
            border: none;
            color: var(--muted);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0;
            line-height: 1;
        }
        .close-btn:hover { color: var(--text); }
        .endpoint-modal-body {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }
        .endpoint-info {
            margin-bottom: 20px;
        }
        .endpoint-info .endpoint-url {
            font-size: 1rem;
            word-break: break-all;
            margin-bottom: 10px;
            color: var(--accent);
        }
        .endpoint-meta {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .endpoint-method {
            font-size: 0.75rem;
            padding: 3px 8px;
            background: rgba(59, 130, 246, 0.2);
            border-radius: 4px;
            color: #3b82f6;
            font-weight: 600;
        }
        .endpoint-status-badge {
            font-size: 0.75rem;
            padding: 3px 10px;
            border-radius: 12px;
            text-transform: uppercase;
        }
        .endpoint-status-badge.discovered { background: rgba(169, 180, 199, 0.2); color: var(--muted); }
        .endpoint-status-badge.tested { background: rgba(124, 92, 255, 0.2); color: var(--accent); }
        .endpoint-status-badge.vulnerable { background: rgba(239, 68, 68, 0.2); color: var(--critical); }
        .endpoint-status-badge.clean { background: rgba(34, 197, 94, 0.2); color: var(--ok); }
        .endpoint-findings h4 {
            color: var(--muted);
            font-size: 0.85rem;
            margin-bottom: 12px;
            text-transform: uppercase;
        }
        .modal-finding {
            padding: 12px;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 3px solid var(--critical);
        }
        .modal-finding.candidate { border-color: var(--warn); }
        .modal-finding.validated { border-color: var(--critical); }
        .modal-finding .finding-title {
            font-weight: 600;
            margin-bottom: 6px;
        }
        .modal-finding .finding-meta {
            font-size: 0.8rem;
            color: var(--muted);
            display: flex;
            gap: 10px;
        }
        .modal-finding .severity {
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            text-transform: uppercase;
        }
        .modal-finding .severity.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); }
        .modal-finding .severity.high { background: rgba(245, 158, 11, 0.2); color: var(--warn); }
        .modal-finding .severity.medium { background: rgba(124, 92, 255, 0.2); color: var(--accent); }
        .modal-finding .severity.low { background: rgba(169, 180, 199, 0.2); color: var(--muted); }
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 999;
            display: none;
        }
        .modal-overlay.active { display: block; }
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
        
        <!-- Executive Summary (default view for leadership) -->
        <div class="exec-summary" id="exec-summary">
            <h2>📊 Executive Summary</h2>
            <div class="exec-grid">
                <div class="exec-card risk-none" id="exec-risk-card">
                    <div class="label">Risk Level</div>
                    <div class="value" id="exec-risk">—</div>
                    <div class="subtext" id="exec-risk-text">Scan in progress</div>
                </div>
                <div class="exec-card">
                    <div class="label">Confirmed Findings</div>
                    <div class="value" style="color: var(--critical);" id="exec-confirmed">0</div>
                    <div class="subtext">Validated vulnerabilities</div>
                </div>
                <div class="exec-card">
                    <div class="label">Under Review</div>
                    <div class="value" style="color: var(--warn);" id="exec-candidates">0</div>
                    <div class="subtext">Candidates being validated</div>
                </div>
                <div class="exec-card">
                    <div class="label">Endpoints Tested</div>
                    <div class="value" style="color: var(--accent);" id="exec-endpoints">0</div>
                    <div class="subtext" id="exec-phase">Initializing...</div>
                </div>
            </div>
            <div class="exec-progress">
                <div class="exec-progress-bar">
                    <div class="exec-progress-fill" id="exec-progress-fill" style="width: 0%"></div>
                </div>
                <div class="exec-progress-text">
                    <span id="exec-duration">0:00 elapsed</span>
                    <span id="exec-progress-pct">0% complete</span>
                    <span id="exec-eta">Calculating ETA...</span>
                </div>
            </div>
        </div>
        
        <!-- View Toggle -->
        <div class="view-toggle">
            <button class="toggle-btn active" id="toggle-summary" onclick="showSummary()">Summary</button>
            <button class="toggle-btn" id="toggle-advanced" onclick="showAdvanced()">Technical Details</button>
        </div>
        
        <!-- Advanced View (hidden by default) -->
        <div class="advanced-view" id="advanced-view">
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
                <h3>ENDPOINTS <span id="endpoints-count" style="color: var(--muted); font-weight: normal;">(0)</span></h3>
                <div class="endpoints-list" id="endpoints-list">
                    <div style="color: var(--muted); padding: 20px; text-align: center;">
                        Discovering endpoints...
                    </div>
                </div>
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
        
        <!-- Live Event Stream (collapsible) -->
        <div class="card" style="margin-bottom: 20px;">
            <h3 style="cursor: pointer;" onclick="toggleEventStream()">
                LIVE EVENT STREAM <span id="event-stream-toggle">▼</span>
            </h3>
            <div class="events" id="events" style="display: none;"></div>
        </div>
        </div><!-- end advanced-view -->
        
        <!-- Endpoint Detail Modal -->
        <div class="endpoint-modal" id="endpoint-modal">
            <div class="endpoint-modal-content">
                <div class="endpoint-modal-header">
                    <h2 id="endpoint-modal-title">Endpoint Details</h2>
                    <button class="close-btn" onclick="closeEndpointModal()">&times;</button>
                </div>
                <div class="endpoint-modal-body">
                    <div class="endpoint-info">
                        <div class="endpoint-url" id="modal-endpoint-url"></div>
                        <div class="endpoint-meta">
                            <span class="endpoint-method" id="modal-endpoint-method">GET</span>
                            <span class="endpoint-status-badge" id="modal-endpoint-status">discovered</span>
                            <span id="modal-endpoint-payloads" style="color: var(--muted);"></span>
                        </div>
                    </div>
                    <div class="endpoint-findings" id="modal-endpoint-findings">
                        <h4>Findings</h4>
                        <div id="modal-findings-list">No findings for this endpoint</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let socket;
        let authenticated = false;
        let findingsCount = 0;
        let candidatesCount = 0;
        let confirmedCount = 0;
        const savedToken = localStorage.getItem('dashboard_token');
        
        // View toggle functions
        function showSummary() {
            document.getElementById('toggle-summary').classList.add('active');
            document.getElementById('toggle-advanced').classList.remove('active');
            document.getElementById('advanced-view').classList.remove('visible');
        }
        
        function showAdvanced() {
            document.getElementById('toggle-advanced').classList.add('active');
            document.getElementById('toggle-summary').classList.remove('active');
            document.getElementById('advanced-view').classList.add('visible');
        }
        
        // Executive summary update
        function updateExecSummary(stats) {
            // Update confirmed vs candidates
            const confirmed = stats.stats?.findings_validated || confirmedCount;
            const candidates = stats.stats?.findings_candidates || candidatesCount;
            
            document.getElementById('exec-confirmed').textContent = confirmed;
            document.getElementById('exec-candidates').textContent = candidates;
            document.getElementById('exec-endpoints').textContent = stats.stats?.endpoints_found || 0;
            
            // Risk level based on confirmed findings
            const riskCard = document.getElementById('exec-risk-card');
            const riskEl = document.getElementById('exec-risk');
            const riskText = document.getElementById('exec-risk-text');
            
            riskCard.className = 'exec-card';
            if (confirmed === 0 && candidates === 0) {
                riskCard.classList.add('risk-none');
                riskEl.textContent = '—';
                riskText.textContent = 'No issues found yet';
            } else if (confirmed === 0) {
                riskCard.classList.add('risk-low');
                riskEl.textContent = 'LOW';
                riskText.textContent = candidates + ' under review';
            } else if (confirmed <= 2) {
                riskCard.classList.add('risk-medium');
                riskEl.textContent = 'MEDIUM';
                riskText.textContent = confirmed + ' confirmed issue(s)';
            } else {
                riskCard.classList.add('risk-high');
                riskEl.textContent = 'HIGH';
                riskText.textContent = confirmed + ' confirmed issues';
            }
            
            // Phase
            if (stats.current_phase) {
                document.getElementById('exec-phase').textContent = 'Phase: ' + stats.current_phase.toUpperCase();
            }
            
            // Progress
            const pct = stats.progress_percentage || 0;
            document.getElementById('exec-progress-fill').style.width = pct + '%';
            document.getElementById('exec-progress-pct').textContent = Math.round(pct) + '% complete';
            
            // Duration
            if (stats.duration_seconds) {
                const mins = Math.floor(stats.duration_seconds / 60);
                const secs = Math.floor(stats.duration_seconds % 60);
                document.getElementById('exec-duration').textContent = mins + ':' + secs.toString().padStart(2, '0') + ' elapsed';
            }
            
            // ETA
            if (stats.eta_seconds && stats.eta_seconds > 0) {
                const etaMins = Math.floor(stats.eta_seconds / 60);
                const etaSecs = Math.floor(stats.eta_seconds % 60);
                document.getElementById('exec-eta').textContent = '~' + etaMins + ':' + etaSecs.toString().padStart(2, '0') + ' remaining';
            } else if (pct >= 100) {
                document.getElementById('exec-eta').textContent = 'Complete';
            }
        }
        
        // If we have a saved token, try to connect automatically
        if (savedToken) { 
            document.getElementById('auth').style.display = 'none';
            tryConnect(savedToken); 
        }
        // Otherwise auth form is already visible (no display:none on it)
        
        function authenticate() {
            console.log('[DEBUG] authenticate() called');
            const token = document.getElementById('token').value;
            console.log('[DEBUG] Token value:', token ? '(has value)' : '(empty)');
            if (!token) {
                showAuthError('Please enter a token');
                return;
            }
            const btn = document.getElementById('auth-btn');
            btn.textContent = 'Connecting...';
            btn.disabled = true;
            hideAuthError();
            console.log('[DEBUG] Calling tryConnect...');
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
            console.log('[DEBUG] tryConnect called with token:', token ? '***' : 'empty');
            socket = io({ 
                auth: { token: token },
                transports: ['websocket', 'polling']
            });
            console.log('[DEBUG] Socket created, waiting for events...');
            
            socket.on('connect', () => {
                console.log('[DEBUG] CONNECTED! Socket ID:', socket.id);
                authenticated = true;
                localStorage.setItem('dashboard_token', token);
                document.getElementById('auth').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                document.getElementById('status-dot').classList.add('active');
                document.getElementById('status-text').textContent = 'Connected';
                resetAuthButton();
            });
            
            socket.on('connect_error', (err) => {
                console.log('[DEBUG] CONNECT ERROR:', err.message);
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
            socket.on('stats_update', (stats) => { updateStats(stats); updateExecSummary(stats); });
            
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
        
        // Endpoint management
        let endpointsData = {};
        let eventStreamVisible = false;
        
        function toggleEventStream() {
            const events = document.getElementById('events');
            const toggle = document.getElementById('event-stream-toggle');
            eventStreamVisible = !eventStreamVisible;
            events.style.display = eventStreamVisible ? 'block' : 'none';
            toggle.textContent = eventStreamVisible ? '▲' : '▼';
        }
        
        function updateEndpointsList(endpoints) {
            const container = document.getElementById('endpoints-list');
            const countEl = document.getElementById('endpoints-count');
            
            if (!endpoints || endpoints.length === 0) {
                return;
            }
            
            countEl.textContent = `(${endpoints.length})`;
            
            // Store endpoints data for modal
            endpoints.forEach(ep => {
                endpointsData[ep.url] = ep;
            });
            
            // Render list
            container.innerHTML = endpoints.map(ep => {
                const findingsCount = ep.findings?.length || 0;
                const findingsBadge = findingsCount > 0 
                    ? `<span class="findings-badge">${findingsCount}</span>` 
                    : '';
                const urlPath = ep.url.replace(/^https?:\/\/[^\/]+/, '') || '/';
                return `
                    <div class="endpoint-item" onclick="openEndpointModal('${escapeHtml(ep.url)}')">
                        <span class="status-indicator ${ep.status}"></span>
                        <span class="endpoint-url" title="${escapeHtml(ep.url)}">${escapeHtml(urlPath)}</span>
                        <span class="endpoint-method">${ep.method || 'GET'}</span>
                        ${findingsBadge}
                    </div>
                `;
            }).join('');
        }
        
        function openEndpointModal(url) {
            const modal = document.getElementById('endpoint-modal');
            const ep = endpointsData[url];
            
            if (!ep) {
                console.error('Endpoint not found:', url);
                return;
            }
            
            // Populate modal
            document.getElementById('modal-endpoint-url').textContent = ep.url;
            document.getElementById('modal-endpoint-method').textContent = ep.method || 'GET';
            
            const statusBadge = document.getElementById('modal-endpoint-status');
            statusBadge.textContent = ep.status;
            statusBadge.className = 'endpoint-status-badge ' + ep.status;
            
            document.getElementById('modal-endpoint-payloads').textContent = 
                ep.payloads_tested > 0 ? `${ep.payloads_tested} payloads tested` : '';
            
            // Render findings
            const findingsContainer = document.getElementById('modal-findings-list');
            if (ep.findings && ep.findings.length > 0) {
                findingsContainer.innerHTML = ep.findings.map(f => `
                    <div class="modal-finding ${f.status}">
                        <div class="finding-title">${escapeHtml(f.title || 'Unknown')}</div>
                        <div class="finding-meta">
                            <span class="severity ${f.severity?.toLowerCase() || 'medium'}">${f.severity || 'Medium'}</span>
                            <span>${f.status === 'validated' ? '✅ Validated' : '⏳ Candidate'}</span>
                            ${f.cwe ? `<span>${f.cwe}</span>` : ''}
                        </div>
                    </div>
                `).join('');
            } else {
                findingsContainer.innerHTML = '<div style="color: var(--muted); padding: 10px;">No findings for this endpoint</div>';
            }
            
            modal.classList.add('active');
            
            // Add overlay click handler
            document.body.insertAdjacentHTML('beforeend', '<div class="modal-overlay active" onclick="closeEndpointModal()"></div>');
        }
        
        function closeEndpointModal() {
            document.getElementById('endpoint-modal').classList.remove('active');
            const overlay = document.querySelector('.modal-overlay');
            if (overlay) overlay.remove();
        }
        
        // Close modal on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeEndpointModal();
        });
        
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
            
            // Update endpoints list
            if (stats.endpoints_with_status) {
                updateEndpointsList(stats.endpoints_with_status);
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
            
            // Handle findings - track candidates vs confirmed separately
            if (event.event_type === 'finding_validated') {
                confirmedCount++;
                addFinding(event.data || {});
            } else if (event.event_type === 'finding_candidate') {
                candidatesCount++;
                addFinding(event.data || {});
            }
            
            // Update target on scan start
            if (event.event_type === 'scan_start') {
                document.getElementById('scan-target').textContent = event.data?.target || '-';
                currentOrgId = event.data?.org_id || 'default';
                findingsCount = 0;
                candidatesCount = 0;
                confirmedCount = 0;
                endpointsData = {};  // Reset endpoints
                document.getElementById('findings').innerHTML = '<div style="color: var(--muted); padding: 20px; text-align: center;">Waiting for findings...</div>';
                document.getElementById('endpoints-list').innerHTML = '<div style="color: var(--muted); padding: 20px; text-align: center;">Discovering endpoints...</div>';
                document.getElementById('endpoints-count').textContent = '(0)';
                // Reset exec summary
                document.getElementById('exec-confirmed').textContent = '0';
                document.getElementById('exec-candidates').textContent = '0';
                document.getElementById('exec-endpoints').textContent = '0';
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
            
            // Track endpoint discoveries in real-time
            if (event.event_type === 'endpoint_discovered') {
                const url = event.data?.url || event.data?.endpoint;
                if (url && !endpointsData[url]) {
                    endpointsData[url] = {
                        url: url,
                        method: event.data?.method || 'GET',
                        status: 'discovered',
                        findings: [],
                        payloads_tested: 0,
                        discovered_at: event.timestamp
                    };
                    // Update endpoints list with new data
                    updateEndpointsList(Object.values(endpointsData).slice(-50));
                }
            }
            
            // Track findings associated with endpoints
            if ((event.event_type === 'finding_validated' || event.event_type === 'finding_candidate') 
                && (event.data?.endpoint || event.data?.url)) {
                const url = event.data?.endpoint || event.data?.url;
                if (endpointsData[url]) {
                    endpointsData[url].status = 'vulnerable';
                    endpointsData[url].findings.push({
                        title: event.data?.title || 'Unknown',
                        severity: event.data?.severity || 'medium',
                        status: event.event_type === 'finding_validated' ? 'validated' : 'candidate',
                        cwe: event.data?.cwe
                    });
                    updateEndpointsList(Object.values(endpointsData).slice(-50));
                }
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
    return jsonify({
        'status': 'healthy',
        'service': 'live-dashboard',
        'started_at': STARTED_AT,
        'version': APP_VERSION,
        'fly_app': os.getenv('FLY_APP_NAME'),
        'fly_region': os.getenv('FLY_REGION'),
        'hostname': os.getenv('HOSTNAME'),
    })


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
    scan_id = request.args.get('scan_id')
    
    # Try storage first for historical data
    if storage and scan_id:
        try:
            return jsonify(storage.get_events(scan_id=scan_id, limit=count))
        except Exception as e:
            print(f"[Dashboard] Storage query failed: {e}")
    
    return jsonify(get_event_stream().get_recent_events(count))


@app.route('/api/scans')
def get_scans():
    """Get scan history from storage."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    limit = request.args.get('limit', 50, type=int)
    status = request.args.get('status')
    
    if storage:
        try:
            scans = storage.list_scans(limit=limit, status=status)
            return jsonify({'status': 'ok', 'scans': scans, 'count': len(scans)})
        except Exception as e:
            print(f"[Dashboard] Failed to list scans: {e}")
    
    # Fallback to in-memory active scans
    return jsonify({'status': 'ok', 'scans': list(active_scans.values()), 'count': len(active_scans)})


@app.route('/api/scans/<scan_id>')
def get_scan_detail(scan_id):
    """Get detailed information for a specific scan."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    if storage:
        try:
            scan = storage.get_scan(scan_id)
            if scan:
                # Include findings
                findings = storage.get_findings(scan_id=scan_id, limit=100)
                events = storage.get_events(scan_id=scan_id, limit=50)
                return jsonify({
                    'status': 'ok',
                    'scan': scan,
                    'findings': findings,
                    'events': events
                })
        except Exception as e:
            print(f"[Dashboard] Failed to get scan detail: {e}")
    
    return jsonify({'status': 'not_found', 'scan_id': scan_id}), 404


@app.route('/api/findings')
def get_findings():
    """Get findings from storage."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    limit = request.args.get('limit', 100, type=int)
    scan_id = request.args.get('scan_id')
    
    if storage:
        try:
            findings = storage.get_findings(scan_id=scan_id, limit=limit)
            return jsonify({'status': 'ok', 'findings': findings, 'count': len(findings)})
        except Exception as e:
            print(f"[Dashboard] Failed to get findings: {e}")
    
    return jsonify({'status': 'ok', 'findings': [], 'count': 0})


@app.route('/api/dashboard-stats')
def get_dashboard_stats():
    """Get aggregated dashboard statistics from storage."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    if storage:
        try:
            stats = storage.get_stats()
            return jsonify({'status': 'ok', 'stats': stats})
        except Exception as e:
            print(f"[Dashboard] Failed to get stats: {e}")
    
    return jsonify({'status': 'ok', 'stats': {}})


@app.route('/api/endpoints')
def get_endpoints():
    """Get all endpoints with their status and findings count."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    limit = request.args.get('limit', 100, type=int)
    stream = get_event_stream()
    endpoints = stream.get_all_endpoints(limit=limit)
    
    return jsonify({
        'status': 'ok',
        'endpoints': endpoints,
        'count': len(endpoints)
    })


@app.route('/api/endpoints/<path:endpoint_url>')
def get_endpoint_detail(endpoint_url):
    """Get detailed info for a specific endpoint including findings."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != DASHBOARD_TOKEN:
        abort(401)
    
    # URL decode the endpoint
    from urllib.parse import unquote
    endpoint_url = unquote(endpoint_url)
    
    stream = get_event_stream()
    endpoint = stream.get_endpoint_details(endpoint_url)
    
    if endpoint:
        return jsonify({
            'status': 'ok',
            'endpoint': endpoint
        })
    
    return jsonify({'status': 'not_found', 'endpoint_url': endpoint_url}), 404


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
    event_dict = event.to_dict()
    
    # Persist to storage
    if storage:
        try:
            storage.save_event(event_dict)
            
            # Save findings separately for easier querying
            if event_type in (EventType.FINDING_VALIDATED, EventType.FINDING_CANDIDATE):
                finding_data = {
                    'scan_id': event.scan_id,
                    'title': payload.get('title', 'Unknown'),
                    'severity': payload.get('severity', 'medium'),
                    'status': 'validated' if event_type == EventType.FINDING_VALIDATED else 'candidate',
                    'cwe': payload.get('cwe', ''),
                    'endpoint': payload.get('endpoint', payload.get('url', '')),
                    **payload
                }
                storage.save_finding(finding_data)
        except Exception as e:
            print(f"[Dashboard] Failed to persist event: {e}")
    
    # Broadcast to all connected WebSocket clients
    socketio.emit('scan_event', event_dict)
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
    
    scan_data = {
        'scan_id': scan_id,
        'org_id': org_id,
        'pid': pid,
        'target': target,
        'started_at': datetime.now().isoformat(),
        'status': 'running'
    }
    
    active_scans[org_id] = scan_data
    
    # Persist to storage
    if storage:
        try:
            storage.save_scan(scan_id, scan_data)
        except Exception as e:
            print(f"[Dashboard] Failed to persist scan: {e}")
    
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
        
        # Persist to storage
        if storage:
            try:
                scan_id = active_scans[org_id].get('scan_id')
                if scan_id:
                    storage.mark_scan_complete(scan_id, status='killed')
            except Exception as e:
                print(f"[Dashboard] Failed to update scan status: {e}")
    
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
