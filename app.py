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
from typing import Optional
from flask import Flask, render_template_string, request, jsonify, abort
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms

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

# Import JWT auth (optional, falls back to simple token if not available)
try:
    from jwt_auth import (
        JWTAuth, get_jwt_auth, jwt_required, admin_required,
        permission_required, release_required
    )
    JWT_AUTH_AVAILABLE = True
except ImportError:
    JWT_AUTH_AVAILABLE = False
    permission_required = None
    release_required = None
    print("[Dashboard] JWT auth not available, using simple token auth")

# Import report status enum from storage
try:
    from storage import ReportStatus
except ImportError:
    ReportStatus = None

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
            --bg: #f8fafc; 
            --card: #ffffff; 
            --text: #1e293b; 
            --muted: #64748b; 
            --border: #e2e8f0;
            --accent: #6d28d9; 
            --accent-light: #f5f3ff;
            --ok: #16a34a; 
            --warn: #d97706; 
            --critical: #dc2626;
            --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: var(--bg); 
            color: var(--text); 
            min-height: 100vh; 
            padding: 24px; 
        }
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 24px; 
            padding-bottom: 20px; 
            border-bottom: 1px solid var(--border); 
        }
        .header h1 { 
            font-size: 1.5rem; 
            font-weight: 700;
            color: var(--accent);
        }
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
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
        }
        .exec-summary h2 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 24px;
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
            padding: 20px;
            background: var(--bg);
            border-radius: 12px;
            border: 1px solid var(--border);
        }
        .exec-card .label {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .exec-card .value {
            font-size: 2.5rem;
            font-weight: 700;
        }
        .exec-card .subtext {
            font-size: 0.8rem;
            color: var(--muted);
            margin-top: 4px;
        }
        .exec-card.risk-none .value { color: var(--ok); }
        .exec-card.risk-low .value { color: var(--accent); }
        .exec-card.risk-medium .value { color: var(--warn); }
        .exec-card.risk-high .value { color: var(--critical); }
        .exec-progress {
            margin-top: 24px;
        }
        .exec-progress-bar {
            height: 10px;
            background: var(--border);
            border-radius: 5px;
            overflow: hidden;
        }
        .exec-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--ok));
            transition: width 0.5s ease;
            border-radius: 5px;
        }
        .exec-progress-text {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.8rem;
            color: var(--muted);
        }
        /* Toggle Button */
        .view-toggle {
            display: flex;
            justify-content: center;
            margin-bottom: 24px;
        }
        .toggle-btn {
            background: var(--card);
            border: 1px solid var(--border);
            color: var(--muted);
            padding: 10px 24px;
            font-size: 0.875rem;
            font-weight: 500;
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
            background: var(--accent-light);
            color: var(--accent);
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
            gap: 20px; 
            margin-bottom: 24px; 
        }
        .grid-3 {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
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
            padding: 20px; 
            border: 1px solid var(--border); 
            box-shadow: var(--shadow);
        }
        .card h3 { 
            color: var(--muted); 
            font-size: 0.75rem; 
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px; 
        }
        .stat-value { 
            font-size: 2rem; 
            font-weight: 700; 
            color: var(--accent); 
        }
        .progress-bar {
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 12px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--ok));
            transition: width 0.3s ease;
        }
        .phase-badge {
            display: inline-block;
            padding: 4px 12px;
            background: var(--accent-light);
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--accent);
            margin-top: 10px;
        }
        .events { 
            max-height: 400px; 
            overflow-y: auto; 
        }
        .event { 
            padding: 10px 12px; 
            border-bottom: 1px solid var(--border); 
            font-size: 0.8rem; 
            display: flex; 
            gap: 12px; 
        }
        .event:hover { background: var(--bg); }
        .event-time { color: var(--muted); min-width: 80px; font-family: 'SF Mono', 'Monaco', monospace; font-size: 0.75rem; }
        .event-type { min-width: 140px; font-weight: 600; }
        .event-type.finding_validated { color: var(--critical); }
        .event-type.finding_candidate { color: var(--warn); }
        .event-type.payload_sent { color: var(--warn); }
        .event-type.endpoint_discovered { color: var(--ok); }
        .event-type.tech_fingerprint { color: #2563eb; }
        .event-type.rag_match { color: var(--accent); }
        .event-type.phase_start { color: #059669; }
        .event-type.scan_start { color: var(--ok); }
        .event-type.scan_complete { color: var(--ok); }
        .event-data { 
            color: var(--muted); 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap;
        }
        .findings { 
            display: flex; 
            flex-direction: column; 
            gap: 10px;
            max-height: 400px;
            overflow-y: auto;
        }
        .finding { 
            padding: 14px; 
            background: var(--bg); 
            border-radius: 10px; 
            border-left: 4px solid var(--critical); 
        }
        .finding.high { border-color: var(--warn); }
        .finding.medium { border-color: var(--accent); }
        .finding.low { border-color: var(--muted); }
        .finding-title { font-weight: 600; margin-bottom: 6px; }
        .finding-rag { 
            font-size: 0.75rem; 
            color: var(--accent); 
            margin-top: 6px; 
        }
        .tech-stack {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .tech-tag {
            display: inline-block;
            padding: 5px 12px;
            background: #dbeafe;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
            color: #1d4ed8;
        }
        .auth-form { 
            max-width: 340px; 
            margin: 100px auto; 
            text-align: center;
            background: var(--card);
            padding: 40px;
            border-radius: 16px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border);
        }
        .auth-form h2 {
            font-size: 1.25rem;
            margin-bottom: 8px;
            color: var(--text);
        }
        .auth-form input { 
            width: 100%; 
            padding: 14px 16px; 
            margin: 12px 0; 
            border-radius: 10px;
            border: 1px solid var(--border); 
            background: var(--bg); 
            color: var(--text);
            font-size: 0.95rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .auth-form input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }
        .auth-form button { 
            width: 100%; 
            padding: 14px; 
            border-radius: 10px; 
            border: none;
            background: var(--accent); 
            color: white; 
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer; 
            transition: background 0.2s, transform 0.1s;
        }
        .auth-form button:hover {
            background: #5b21b6;
        }
        .auth-form button:active {
            transform: scale(0.98);
        }
        .faraday-link {
            margin-top: 16px;
            padding: 12px;
            background: #dcfce7;
            border-radius: 10px;
            border: 1px solid #bbf7d0;
        }
        .faraday-link a {
            color: var(--ok);
            text-decoration: none;
            font-weight: 500;
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
            background: #b91c1c;
            transform: scale(1.02);
        }
        .kill-btn:disabled {
            background: var(--border);
            color: var(--muted);
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
            background: rgba(0,0,0,0.4);
            backdrop-filter: blur(4px);
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
            border-radius: 16px;
            padding: 32px;
            max-width: 420px;
            text-align: center;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border);
        }
        .kill-modal h2 {
            color: var(--critical);
            margin-bottom: 16px;
            font-size: 1.25rem;
        }
        .kill-modal p {
            color: var(--muted);
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .kill-modal-buttons {
            display: flex;
            gap: 12px;
            justify-content: center;
        }
        .kill-modal-buttons button {
            padding: 12px 28px;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .kill-modal-buttons .cancel {
            background: var(--bg);
            color: var(--text);
            border: 1px solid var(--border);
        }
        .kill-modal-buttons .cancel:hover {
            background: var(--border);
        }
        .kill-modal-buttons .confirm {
            background: var(--critical);
            color: white;
        }
        .kill-modal-buttons .confirm:hover {
            background: #b91c1c;
        }
        /* Endpoints List Styles */
        .endpoints-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .endpoint-item {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: background 0.2s ease;
        }
        .endpoint-item:hover {
            background: var(--accent-light);
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
            padding: 3px 8px;
            background: var(--bg);
            border-radius: 4px;
            color: var(--muted);
            font-weight: 500;
        }
        .endpoint-item .findings-badge {
            font-size: 0.75rem;
            padding: 3px 10px;
            background: var(--critical);
            border-radius: 10px;
            color: white;
            font-weight: 600;
        }
        /* Endpoint Modal Styles */
        .endpoint-modal {
            position: fixed;
            top: 0;
            right: -500px;
            width: 500px;
            height: 100vh;
            background: var(--card);
            border-left: 1px solid var(--border);
            box-shadow: -4px 0 12px rgba(0,0,0,0.08);
            z-index: 1000;
            transition: right 0.3s ease;
            display: flex;
            flex-direction: column;
        }
        .endpoint-modal.active {
            right: 0;
        }
        .endpoint-modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .endpoint-modal-header h2 {
            font-size: 1.1rem;
            font-weight: 600;
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
            transition: color 0.2s;
        }
        .close-btn:hover { color: var(--text); }
        .endpoint-modal-body {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
        }
        .endpoint-info {
            margin-bottom: 24px;
        }
        .endpoint-info .endpoint-url {
            font-size: 1rem;
            font-weight: 500;
            word-break: break-all;
            margin-bottom: 12px;
            color: var(--accent);
        }
        .endpoint-meta {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .endpoint-method {
            font-size: 0.7rem;
            padding: 4px 10px;
            background: #dbeafe;
            border-radius: 4px;
            color: #1d4ed8;
            font-weight: 600;
        }
        .endpoint-status-badge {
            font-size: 0.7rem;
            padding: 4px 12px;
            border-radius: 12px;
            text-transform: uppercase;
            font-weight: 600;
        }
        .endpoint-status-badge.discovered { background: #f1f5f9; color: var(--muted); }
        .endpoint-status-badge.tested { background: var(--accent-light); color: var(--accent); }
        .endpoint-status-badge.vulnerable { background: #fef2f2; color: var(--critical); }
        .endpoint-status-badge.clean { background: #dcfce7; color: var(--ok); }
        .endpoint-findings h4 {
            color: var(--muted);
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .modal-finding {
            padding: 14px;
            background: var(--bg);
            border-radius: 10px;
            margin-bottom: 12px;
            border-left: 4px solid var(--critical);
        }
        .modal-finding.candidate { border-color: var(--warn); }
        .modal-finding.validated { border-color: var(--critical); }
        .modal-finding .finding-title {
            font-weight: 600;
            margin-bottom: 8px;
        }
        .modal-finding .finding-meta {
            font-size: 0.8rem;
            color: var(--muted);
            display: flex;
            gap: 10px;
        }
        .modal-finding .severity {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .modal-finding .severity.critical { background: #fef2f2; color: var(--critical); }
        .modal-finding .severity.high { background: #fef3c7; color: var(--warn); }
        .modal-finding .severity.medium { background: var(--accent-light); color: var(--accent); }
        .modal-finding .severity.low { background: #f1f5f9; color: var(--muted); }
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.3);
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

# Admin Dashboard HTML - Multi-client view
ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Agentic Security - Admin Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        :root { 
            --bg: #f8fafc; 
            --card: #ffffff; 
            --text: #1e293b; 
            --muted: #64748b;
            --accent: #6d28d9;
            --accent-light: #f5f3ff;
            --success: #16a34a;
            --warning: #d97706;
            --danger: #dc2626;
            --border: #e2e8f0;
            --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            min-height: 100vh;
        }
        .header {
            background: var(--card);
            padding: 1.25rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: var(--shadow);
        }
        .header h1 {
            font-size: 1.375rem;
            font-weight: 700;
            color: var(--accent);
        }
        .header-badge {
            background: var(--accent);
            color: white;
            padding: 0.375rem 0.875rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: var(--shadow);
        }
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--accent);
        }
        .stat-label {
            color: var(--muted);
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.5rem;
        }
        .section-title {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text);
        }
        .clients-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .client-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: var(--shadow);
        }
        .client-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        .client-header {
            background: var(--bg);
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }
        .client-name {
            font-weight: 600;
            font-size: 1rem;
            color: var(--text);
        }
        .client-badge {
            background: var(--accent);
            color: white;
            padding: 0.25rem 0.625rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        .client-scans {
            padding: 1rem 1.25rem;
        }
        .scan-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            background: var(--bg);
            border-radius: 8px;
            margin-bottom: 0.5rem;
            border: 1px solid var(--border);
        }
        .scan-target {
            font-size: 0.875rem;
            color: var(--text);
            font-weight: 500;
        }
        .scan-status {
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.25rem 0.625rem;
            border-radius: 6px;
        }
        .scan-status.running {
            background: var(--accent-light);
            color: var(--accent);
        }
        .scan-status.completed {
            background: #dcfce7;
            color: var(--success);
        }
        .scan-status.failed {
            background: #fef2f2;
            color: var(--danger);
        }
        .client-actions {
            padding: 1rem 1.25rem;
            border-top: 1px solid var(--border);
            display: flex;
            gap: 0.5rem;
        }
        .btn {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 0.8rem;
            font-weight: 500;
            font-family: inherit;
            transition: all 0.2s;
        }
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        .btn-primary:hover {
            background: #5b21b6;
        }
        .btn-secondary {
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-secondary:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .btn-danger {
            background: #fef2f2;
            color: var(--danger);
            border: 1px solid #fecaca;
        }
        .btn-danger:hover {
            background: var(--danger);
            color: white;
        }
        .all-scans {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        .all-scans-header {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border);
            background: var(--bg);
        }
        .scans-table {
            width: 100%;
            border-collapse: collapse;
        }
        .scans-table th,
        .scans-table td {
            padding: 1rem 1.25rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        .scans-table th {
            background: var(--bg);
            color: var(--muted);
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .scans-table tr:hover td {
            background: var(--accent-light);
        }
        .no-data {
            text-align: center;
            padding: 3rem;
            color: var(--muted);
        }
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 3rem;
            color: var(--muted);
        }
        .loading::after {
            content: '';
            width: 20px;
            height: 20px;
            border: 2px solid var(--accent);
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 0.5rem;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--muted);
            font-size: 0.8rem;
        }
        .footer a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Agentic Security Admin</h1>
        <div style="display: flex; align-items: center; gap: 16px;">
            <a href="/admin/reports" style="color: white; text-decoration: none; padding: 10px 18px; background: var(--accent); border-radius: 8px; font-size: 0.85rem; font-weight: 600; transition: all 0.2s;">
                📋 Manage Reports
            </a>
            <span class="header-badge">Multi-Tenant Control</span>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalClients">-</div>
                <div class="stat-label">Active Clients</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalScans">-</div>
                <div class="stat-label">Running Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalFindings">-</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uptime">-</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>
        
        <h2 class="section-title">📊 Clients Overview</h2>
        <div class="clients-grid" id="clientsGrid">
            <div class="loading">Loading clients...</div>
        </div>
        
        <h2 class="section-title">🔄 All Active Scans</h2>
        <div class="all-scans">
            <table class="scans-table">
                <thead>
                    <tr>
                        <th>Client</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="scansTableBody">
                    <tr><td colspan="5" class="loading">Loading scans...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="footer">
        <a href="/">← Back to Dashboard</a> | 
        Admin Dashboard v1.0
    </div>
    
    <script>
        const TOKEN = new URLSearchParams(window.location.search).get('token') || '';
        const API_BASE = '';
        
        async function fetchWithAuth(url) {
            const res = await fetch(url, {
                headers: { 'Authorization': `Bearer ${TOKEN}` }
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        }
        
        async function loadClients() {
            try {
                const data = await fetchWithAuth('/api/admin/clients');
                document.getElementById('totalClients').textContent = data.total_clients;
                document.getElementById('totalScans').textContent = data.total_scans;
                
                const grid = document.getElementById('clientsGrid');
                if (data.clients.length === 0) {
                    grid.innerHTML = '<div class="no-data">No active clients</div>';
                    return;
                }
                
                grid.innerHTML = data.clients.map(client => `
                    <div class="client-card">
                        <div class="client-header">
                            <span class="client-name">${escapeHtml(client.client_id)}</span>
                            <span class="client-badge">${client.active_scans} scans</span>
                        </div>
                        <div class="client-scans">
                            ${client.scans.map(scan => `
                                <div class="scan-item">
                                    <span class="scan-target">${escapeHtml(scan.target || 'Unknown')}</span>
                                    <span class="scan-status ${scan.status || 'running'}">${scan.status || 'running'}</span>
                                </div>
                            `).join('')}
                        </div>
                        <div class="client-actions">
                            <button class="btn btn-primary" onclick="viewClient('${client.client_id}')">View Dashboard</button>
                            <button class="btn btn-secondary" onclick="killClientScans('${client.client_id}')">Kill All</button>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                document.getElementById('clientsGrid').innerHTML = 
                    `<div class="no-data">Error loading clients: ${e.message}</div>`;
            }
        }
        
        async function loadAllScans() {
            try {
                const data = await fetchWithAuth('/api/admin/all-scans');
                const tbody = document.getElementById('scansTableBody');
                
                if (data.scans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="no-data">No active scans</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.scans.map(scan => `
                    <tr>
                        <td>${escapeHtml(scan.client_id)}</td>
                        <td>${escapeHtml(scan.target || 'Unknown')}</td>
                        <td><span class="scan-status ${scan.status || 'running'}">${scan.status || 'running'}</span></td>
                        <td>${formatTime(scan.started_at)}</td>
                        <td>
                            <button class="btn btn-danger" onclick="killScan('${scan.org_id}')">Kill</button>
                        </td>
                    </tr>
                `).join('');
            } catch (e) {
                document.getElementById('scansTableBody').innerHTML = 
                    `<tr><td colspan="5" class="no-data">Error: ${e.message}</td></tr>`;
            }
        }
        
        async function loadStats() {
            try {
                const data = await fetchWithAuth('/api/stats');
                document.getElementById('totalFindings').textContent = 
                    (data.critical || 0) + (data.high || 0) + (data.medium || 0) + (data.low || 0);
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }
        
        function viewClient(clientId) {
            // Get client-scoped token and redirect
            fetchWithAuth(`/api/admin/switch-client/${clientId}`)
                .then(data => {
                    window.open(data.dashboard_url, '_blank');
                })
                .catch(e => alert('Failed to switch client: ' + e.message));
        }
        
        async function killScan(orgId) {
            if (!confirm('Kill this scan?')) return;
            try {
                await fetch('/api/scan/kill', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${TOKEN}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ org_id: orgId, reason: 'Admin kill' })
                });
                loadAllScans();
                loadClients();
            } catch (e) {
                alert('Failed to kill scan: ' + e.message);
            }
        }
        
        async function killClientScans(clientId) {
            if (!confirm(`Kill all scans for ${clientId}?`)) return;
            // Kill all scans for this client
            try {
                const data = await fetchWithAuth('/api/admin/all-scans');
                const clientScans = data.scans.filter(s => s.client_id === clientId);
                for (const scan of clientScans) {
                    await fetch('/api/scan/kill', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${TOKEN}`,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ org_id: scan.org_id, reason: 'Admin bulk kill' })
                    });
                }
                loadAllScans();
                loadClients();
            } catch (e) {
                alert('Failed: ' + e.message);
            }
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>"']/g, m => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            })[m]);
        }
        
        function formatTime(iso) {
            if (!iso) return '-';
            const d = new Date(iso);
            return d.toLocaleTimeString();
        }
        
        function updateUptime() {
            fetch('/health')
                .then(r => r.json())
                .then(data => {
                    if (data.started_at) {
                        const start = new Date(data.started_at);
                        const now = new Date();
                        const diff = Math.floor((now - start) / 1000);
                        const hours = Math.floor(diff / 3600);
                        const mins = Math.floor((diff % 3600) / 60);
                        document.getElementById('uptime').textContent = `${hours}h ${mins}m`;
                    }
                });
        }
        
        // Initial load
        loadClients();
        loadAllScans();
        loadStats();
        updateUptime();
        
        // Refresh every 10 seconds
        setInterval(() => {
            loadClients();
            loadAllScans();
            loadStats();
        }, 10000);
        
        setInterval(updateUptime, 60000);
    </script>
</body>
</html>
"""

# Client Self-Service Portal HTML
CLIENT_PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Agentic Security - Client Portal</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        :root { 
            --bg: #f8fafc; 
            --card: #ffffff; 
            --text: #1e293b; 
            --muted: #64748b;
            --accent: #16a34a;
            --accent-light: #dcfce7;
            --success: #16a34a;
            --warning: #d97706;
            --danger: #dc2626;
            --border: #e2e8f0;
            --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            min-height: 100vh;
        }
        .header {
            background: var(--card);
            padding: 1.25rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: var(--shadow);
        }
        .header h1 {
            font-size: 1.375rem;
            font-weight: 700;
            color: var(--text);
        }
        .header h1 span {
            color: var(--accent);
        }
        .client-badge {
            background: var(--accent);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .welcome-card {
            background: var(--accent-light);
            border: 1px solid #bbf7d0;
            border-radius: 14px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .welcome-card h2 {
            font-size: 1.375rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            color: var(--text);
        }
        .welcome-card p {
            color: var(--muted);
        }
        .stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }
        @media (max-width: 768px) {
            .stats-row { grid-template-columns: repeat(2, 1fr); }
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }
        .stat-label {
            color: var(--muted);
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }
        .section {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            margin-bottom: 2rem;
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        .section-header {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg);
        }
        .section-header h3 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text);
        }
        .section-content {
            padding: 1.5rem;
        }
        .scan-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .scan-card {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .scan-card:hover {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }
        .scan-info h4 {
            font-size: 0.95rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .scan-info p {
            font-size: 0.8rem;
            color: var(--muted);
        }
        .scan-meta {
            text-align: right;
        }
        .status-badge {
            display: inline-block;
            padding: 0.3rem 0.875rem;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        .status-badge.running {
            background: var(--accent-light);
            color: var(--accent);
        }
        .status-badge.completed {
            background: #dcfce7;
            color: var(--success);
        }
        .status-badge.failed {
            background: #fef2f2;
            color: var(--danger);
        }
        .findings-summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
        }
        .finding-type {
            text-align: center;
            padding: 1.25rem;
            border-radius: 10px;
            background: var(--bg);
            border: 1px solid var(--border);
        }
        .finding-type.critical {
            border-left: 4px solid #dc2626;
        }
        .finding-type.high {
            border-left: 4px solid #ea580c;
        }
        .finding-type.medium {
            border-left: 4px solid #d97706;
        }
        .finding-type.low {
            border-left: 4px solid #0891b2;
        }
        .finding-count {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text);
        }
        .finding-label {
            font-size: 0.7rem;
            font-weight: 500;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-top: 4px;
        }
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: var(--muted);
        }
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 1.25rem;
            opacity: 0.4;
        }
        .empty-state p {
            font-size: 0.95rem;
        }
        .btn {
            padding: 0.625rem 1.25rem;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.2s;
        }
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        .btn-primary:hover {
            background: #15803d;
        }
        .token-display {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            color: var(--text);
        }
        .token-display.masked {
            color: var(--muted);
        }
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--muted);
            font-size: 0.8rem;
        }
        .footer a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 500;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ <span>Agentic</span> Security</h1>
        <span class="client-badge" id="clientBadge">Loading...</span>
    </div>
    
    <div class="container">
        <div class="welcome-card">
            <h2>Welcome back!</h2>
            <p>Monitor your security scans and findings from one place.</p>
        </div>
        
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value" id="activeScans">0</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalFindings">0</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="criticalCount">0</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="lastScan">-</div>
                <div class="stat-label">Last Scan</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h3>📊 Findings Overview</h3>
            </div>
            <div class="section-content">
                <div class="findings-summary">
                    <div class="finding-type critical">
                        <div class="finding-count" id="criticalFindings">0</div>
                        <div class="finding-label">Critical</div>
                    </div>
                    <div class="finding-type high">
                        <div class="finding-count" id="highFindings">0</div>
                        <div class="finding-label">High</div>
                    </div>
                    <div class="finding-type medium">
                        <div class="finding-count" id="mediumFindings">0</div>
                        <div class="finding-label">Medium</div>
                    </div>
                    <div class="finding-type low">
                        <div class="finding-count" id="lowFindings">0</div>
                        <div class="finding-label">Low</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h3>🔄 Recent Scans</h3>
                <button class="btn btn-primary" onclick="window.open('/?token=' + TOKEN, '_blank')">
                    Live Dashboard →
                </button>
            </div>
            <div class="section-content">
                <div class="scan-list" id="scanList">
                    <div class="empty-state">Loading scans...</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h3>🔑 API Access</h3>
            </div>
            <div class="section-content">
                <p style="margin-bottom: 1rem; color: #64748b;">
                    Use this token to connect to the live dashboard or API:
                </p>
                <div class="token-display masked" id="tokenDisplay">
                    ••••••••••••••••••••••••••••••••
                </div>
                <button class="btn btn-primary" style="margin-top: 1rem;" onclick="toggleToken()">
                    Show Token
                </button>
            </div>
        </div>
    </div>
    
    <div class="footer">
        Client Portal v1.0 | <a href="/" style="color: var(--accent);">Main Dashboard</a>
    </div>
    
    <script>
        const TOKEN = new URLSearchParams(window.location.search).get('token') || '';
        let clientId = 'Unknown';
        let tokenVisible = false;
        
        async function fetchWithAuth(url) {
            const res = await fetch(url, {
                headers: { 'Authorization': `Bearer ${TOKEN}` }
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        }
        
        async function validateToken() {
            try {
                const data = await fetchWithAuth('/api/auth/validate');
                if (data.valid) {
                    clientId = data.client_id;
                    document.getElementById('clientBadge').textContent = clientId;
                }
            } catch (e) {
                document.getElementById('clientBadge').textContent = 'Invalid Token';
            }
        }
        
        async function loadScans() {
            try {
                const data = await fetchWithAuth('/api/scan/status');
                const scanList = document.getElementById('scanList');
                
                // Filter to only this client's scans
                const scans = Object.values(data.scans || {}).filter(s => 
                    s.client_id === clientId || !s.client_id
                );
                
                document.getElementById('activeScans').textContent = 
                    scans.filter(s => s.status === 'running').length;
                
                if (scans.length === 0) {
                    scanList.innerHTML = '<div class="empty-state">No scans yet. Start one to see results here.</div>';
                    return;
                }
                
                // Update last scan
                if (scans.length > 0) {
                    const latest = scans.sort((a, b) => 
                        new Date(b.started_at || 0) - new Date(a.started_at || 0)
                    )[0];
                    document.getElementById('lastScan').textContent = 
                        formatRelativeTime(latest.started_at);
                }
                
                scanList.innerHTML = scans.slice(0, 5).map(scan => `
                    <div class="scan-card">
                        <div class="scan-info">
                            <h4>${escapeHtml(scan.target || 'Unknown target')}</h4>
                            <p>Scan ID: ${escapeHtml(scan.scan_id || scan.org_id)}</p>
                        </div>
                        <div class="scan-meta">
                            <span class="status-badge ${scan.status || 'running'}">${scan.status || 'running'}</span>
                            <p style="font-size: 0.75rem; color: #64748b; margin-top: 0.5rem;">
                                ${formatTime(scan.started_at)}
                            </p>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                document.getElementById('scanList').innerHTML = 
                    `<div class="empty-state">Error loading scans</div>`;
            }
        }
        
        async function loadStats() {
            try {
                const data = await fetchWithAuth('/api/stats');
                document.getElementById('criticalFindings').textContent = data.critical || 0;
                document.getElementById('highFindings').textContent = data.high || 0;
                document.getElementById('mediumFindings').textContent = data.medium || 0;
                document.getElementById('lowFindings').textContent = data.low || 0;
                document.getElementById('criticalCount').textContent = data.critical || 0;
                document.getElementById('totalFindings').textContent = 
                    (data.critical || 0) + (data.high || 0) + (data.medium || 0) + (data.low || 0);
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }
        
        function toggleToken() {
            const display = document.getElementById('tokenDisplay');
            tokenVisible = !tokenVisible;
            display.textContent = tokenVisible ? TOKEN : '••••••••••••••••••••••••••••••••';
            display.classList.toggle('masked', !tokenVisible);
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>"']/g, m => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            })[m]);
        }
        
        function formatTime(iso) {
            if (!iso) return '-';
            return new Date(iso).toLocaleString();
        }
        
        function formatRelativeTime(iso) {
            if (!iso) return '-';
            const diff = (Date.now() - new Date(iso)) / 1000;
            if (diff < 60) return 'Just now';
            if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
            return `${Math.floor(diff/86400)}d ago`;
        }
        
        // Initialize
        validateToken().then(() => {
            loadScans();
            loadStats();
        });
        
        // Refresh every 30 seconds
        setInterval(() => {
            loadScans();
            loadStats();
        }, 30000);
    </script>
</body>
</html>
"""


# Admin Reports Management HTML
ADMIN_REPORTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Agentic Security - Report Management</title>
    <style>
        :root { 
            --bg: #f8fafc; 
            --card: #ffffff; 
            --text: #1e293b; 
            --muted: #64748b;
            --accent: #6d28d9;
            --accent-light: #f5f3ff;
            --success: #16a34a;
            --warning: #d97706;
            --danger: #dc2626;
            --border: #e2e8f0;
            --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
            --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04);
            --staged: #d97706;
            --approved: #2563eb;
            --released: #16a34a;
            --revoked: #dc2626;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            min-height: 100vh;
        }
        .header {
            background: var(--card);
            padding: 1.25rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: var(--shadow);
        }
        .header h1 {
            font-size: 1.375rem;
            font-weight: 700;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-nav {
            display: flex;
            gap: 8px;
        }
        .header-nav a {
            color: var(--muted);
            text-decoration: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        .header-nav a:hover {
            background: var(--accent-light);
            color: var(--accent);
        }
        .header-nav a.active {
            background: var(--accent);
            color: white;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            text-align: center;
            box-shadow: var(--shadow);
        }
        .stat-card .count {
            font-size: 2.5rem;
            font-weight: 700;
        }
        .stat-card .label {
            color: var(--muted);
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 6px;
        }
        .stat-card.staged .count { color: var(--staged); }
        .stat-card.approved .count { color: var(--approved); }
        .stat-card.released .count { color: var(--released); }
        .stat-card.revoked .count { color: var(--revoked); }
        
        .filter-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 24px;
        }
        .filter-btn {
            padding: 10px 20px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-weight: 500;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .filter-btn.active {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }
        
        .reports-grid {
            display: grid;
            gap: 16px;
        }
        .report-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            transition: all 0.2s;
            box-shadow: var(--shadow);
        }
        .report-card:hover {
            border-color: var(--accent);
            box-shadow: var(--shadow-lg);
        }
        .report-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }
        .report-title {
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--text);
        }
        .report-meta {
            color: var(--muted);
            font-size: 0.8rem;
            margin-top: 4px;
        }
        .status-badge {
            padding: 5px 14px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .status-badge.staged { background: #fef3c7; color: var(--staged); }
        .status-badge.approved { background: #dbeafe; color: var(--approved); }
        .status-badge.released { background: #dcfce7; color: var(--released); }
        .status-badge.revoked { background: #fef2f2; color: var(--revoked); }
        
        .report-details {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 16px;
            padding: 18px;
            background: var(--bg);
            border-radius: 10px;
            border: 1px solid var(--border);
        }
        .detail-item {
            text-align: center;
        }
        .detail-value {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text);
        }
        .detail-label {
            color: var(--muted);
            font-size: 0.7rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-top: 4px;
        }
        
        .report-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        .btn {
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        .btn-primary:hover {
            background: #5b21b6;
            transform: translateY(-1px);
        }
        .btn-success {
            background: var(--success);
            color: white;
        }
        .btn-success:hover {
            background: #15803d;
        }
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        .btn-danger:hover {
            background: #b91c1c;
        }
        .btn-secondary {
            background: var(--bg);
            color: var(--text);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }
        
        /* Modal */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.4);
            backdrop-filter: blur(4px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-overlay.active {
            display: flex;
        }
        .modal {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            max-width: 500px;
            width: 90%;
            box-shadow: var(--shadow-lg);
        }
        .modal h2 {
            margin-bottom: 20px;
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--text);
        }
        .modal-body {
            margin-bottom: 24px;
        }
        .modal-body p {
            color: var(--muted);
            line-height: 1.6;
        }
        .confirmation-box {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            margin: 18px 0;
        }
        .confirmation-box .label {
            color: var(--muted);
            font-size: 0.8rem;
            font-weight: 500;
            margin-bottom: 10px;
        }
        .confirmation-box .value {
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 0.95rem;
            color: var(--accent);
            background: var(--accent-light);
            padding: 14px;
            border-radius: 8px;
            font-weight: 600;
        }
        .confirmation-input {
            width: 100%;
            padding: 14px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text);
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 0.95rem;
            margin-top: 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .confirmation-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }
        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        
        .empty-state {
            text-align: center;
            padding: 80px 40px;
            color: var(--muted);
            background: var(--card);
            border-radius: 14px;
            border: 1px solid var(--border);
        }
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 20px;
            opacity: 0.4;
        }
        .empty-state p {
            font-size: 1rem;
        }
        
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            padding: 16px 24px;
            border-radius: 10px;
            color: white;
            font-weight: 600;
            z-index: 1001;
            box-shadow: var(--shadow-lg);
            animation: slideIn 0.3s ease;
        }
        .toast.success { background: var(--success); }
        .toast.error { background: var(--danger); }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        /* Textarea styling */
        textarea {
            width: 100%;
            padding: 14px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text);
            font-family: inherit;
            font-size: 0.95rem;
            resize: vertical;
            min-height: 80px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }
        
        @media (max-width: 768px) {
            .stats-bar { grid-template-columns: repeat(2, 1fr); }
            .report-details { grid-template-columns: repeat(2, 1fr); }
            .filter-bar { flex-wrap: wrap; }
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>📋 Report Management</h1>
        <nav class="header-nav">
            <a href="/admin">Admin Dashboard</a>
            <a href="/admin/reports" class="active">Reports</a>
            <a href="/">Live Scans</a>
        </nav>
    </header>
    
    <div class="container">
        <!-- Stats Bar -->
        <div class="stats-bar">
            <div class="stat-card staged">
                <div class="count" id="staged-count">0</div>
                <div class="label">Awaiting Review</div>
            </div>
            <div class="stat-card approved">
                <div class="count" id="approved-count">0</div>
                <div class="label">Ready to Release</div>
            </div>
            <div class="stat-card released">
                <div class="count" id="released-count">0</div>
                <div class="label">Released to Clients</div>
            </div>
            <div class="stat-card revoked">
                <div class="count" id="revoked-count">0</div>
                <div class="label">Revoked</div>
            </div>
        </div>
        
        <!-- Filter Bar -->
        <div class="filter-bar">
            <button class="filter-btn active" data-filter="pending">⏳ Pending Action</button>
            <button class="filter-btn" data-filter="STAGED">📝 Staged</button>
            <button class="filter-btn" data-filter="APPROVED">✅ Approved</button>
            <button class="filter-btn" data-filter="RELEASED">🚀 Released</button>
            <button class="filter-btn" data-filter="all">📊 All Reports</button>
        </div>
        
        <!-- Reports Grid -->
        <div class="reports-grid" id="reports-container">
            <div class="empty-state">
                <div>Loading reports...</div>
            </div>
        </div>
    </div>
    
    <!-- Approve Modal -->
    <div class="modal-overlay" id="approve-modal">
        <div class="modal">
            <h2>✅ Approve Report</h2>
            <div class="modal-body">
                <p>You are about to approve this report for release:</p>
                <div class="confirmation-box">
                    <div class="label">Report</div>
                    <div class="value" id="approve-report-title">-</div>
                </div>
                <div class="confirmation-box">
                    <div class="label">Client</div>
                    <div class="value" id="approve-client-id">-</div>
                </div>
                <textarea id="approve-notes" class="confirmation-input" 
                    placeholder="Optional: Add approval notes..." rows="3"></textarea>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('approve-modal')">Cancel</button>
                <button class="btn btn-success" onclick="confirmApprove()">Approve Report</button>
            </div>
        </div>
    </div>
    
    <!-- Release Modal -->
    <div class="modal-overlay" id="release-modal">
        <div class="modal">
            <h2>🚀 Release Report to Client</h2>
            <div class="modal-body">
                <p>⚠️ This will make the report visible to the client.</p>
                <div class="confirmation-box">
                    <div class="label">Client</div>
                    <div class="value" id="release-client-id">-</div>
                </div>
                <div class="confirmation-box">
                    <div class="label">Report Title</div>
                    <div class="value" id="release-report-title">-</div>
                </div>
                <div class="confirmation-box">
                    <div class="label">Report Hash</div>
                    <div class="value" id="release-hash">-</div>
                </div>
                <div class="confirmation-box">
                    <div class="label">Type this to confirm release:</div>
                    <div class="value" id="release-confirmation-string">RELEASE xxx 1</div>
                </div>
                <input type="text" id="release-confirmation-input" class="confirmation-input" 
                    placeholder="Type the confirmation string exactly..." autocomplete="off">
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('release-modal')">Cancel</button>
                <button class="btn btn-primary" id="release-confirm-btn" onclick="confirmRelease()" disabled>
                    Release to Client
                </button>
            </div>
        </div>
    </div>
    
    <!-- View Details Modal -->
    <div class="modal-overlay" id="details-modal">
        <div class="modal" style="max-width: 700px;">
            <h2>📄 Report Details</h2>
            <div class="modal-body" id="details-content">
                Loading...
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('details-modal')">Close</button>
            </div>
        </div>
    </div>
    
    <script>
        const token = new URLSearchParams(window.location.search).get('token') || '';
        let currentFilter = 'pending';
        let reports = [];
        let currentReportId = null;
        
        function getHeaders() {
            return {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            };
        }
        
        async function loadReports() {
            try {
                const response = await fetch('/api/admin/reports?limit=100', {
                    headers: getHeaders()
                });
                const data = await response.json();
                reports = data.reports || [];
                
                // Update stats
                const counts = data.status_counts || {};
                document.getElementById('staged-count').textContent = counts.STAGED || 0;
                document.getElementById('approved-count').textContent = counts.APPROVED || 0;
                document.getElementById('released-count').textContent = counts.RELEASED || 0;
                document.getElementById('revoked-count').textContent = counts.REVOKED || 0;
                
                renderReports();
            } catch (err) {
                console.error('Failed to load reports:', err);
                showToast('Failed to load reports', 'error');
            }
        }
        
        function renderReports() {
            const container = document.getElementById('reports-container');
            let filtered = reports;
            
            if (currentFilter === 'pending') {
                filtered = reports.filter(r => r.status === 'STAGED' || r.status === 'APPROVED');
            } else if (currentFilter !== 'all') {
                filtered = reports.filter(r => r.status === currentFilter);
            }
            
            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        <div>No reports found</div>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = filtered.map(r => `
                <div class="report-card">
                    <div class="report-header">
                        <div>
                            <div class="report-title">${escapeHtml(r.title || 'Untitled Report')}</div>
                            <div class="report-meta">
                                ${escapeHtml(r.client_id)} • ${escapeHtml(r.scan_id)} • v${r.version || 1}
                            </div>
                        </div>
                        <span class="status-badge ${r.status.toLowerCase()}">${r.status}</span>
                    </div>
                    <div class="report-details">
                        <div class="detail-item">
                            <div class="detail-value">${r.findings_count || 0}</div>
                            <div class="detail-label">Findings</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-value">${formatDate(r.created_at)}</div>
                            <div class="detail-label">Created</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-value">${r.approved_by || '-'}</div>
                            <div class="detail-label">Approved By</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-value">${r.released_by || '-'}</div>
                            <div class="detail-label">Released By</div>
                        </div>
                    </div>
                    <div class="report-actions">
                        <button class="btn btn-secondary" onclick="viewDetails('${r.report_id}')">
                            View Details
                        </button>
                        ${getActionButtons(r)}
                    </div>
                </div>
            `).join('');
        }
        
        function getActionButtons(report) {
            if (report.status === 'STAGED') {
                return `<button class="btn btn-success" onclick="openApprove('${report.report_id}')">
                    ✅ Approve
                </button>`;
            }
            if (report.status === 'APPROVED') {
                return `<button class="btn btn-primary" onclick="openRelease('${report.report_id}')">
                    🚀 Release to Client
                </button>`;
            }
            if (report.status === 'RELEASED') {
                return `<button class="btn btn-danger" onclick="revokeReport('${report.report_id}')">
                    ⛔ Revoke
                </button>`;
            }
            return '';
        }
        
        function formatDate(dateStr) {
            if (!dateStr) return '-';
            const d = new Date(dateStr);
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        
        // Filter handlers
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.filter;
                renderReports();
            });
        });
        
        // Modal functions
        function openModal(id) {
            document.getElementById(id).classList.add('active');
        }
        
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
            currentReportId = null;
        }
        
        function openApprove(reportId) {
            const report = reports.find(r => r.report_id === reportId);
            if (!report) return;
            
            currentReportId = reportId;
            document.getElementById('approve-report-title').textContent = report.title || 'Untitled';
            document.getElementById('approve-client-id').textContent = report.client_id;
            document.getElementById('approve-notes').value = '';
            openModal('approve-modal');
        }
        
        async function confirmApprove() {
            if (!currentReportId) return;
            
            const notes = document.getElementById('approve-notes').value;
            
            try {
                const response = await fetch(`/api/admin/reports/${currentReportId}/approve`, {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify({ notes })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showToast('Report approved successfully!', 'success');
                    closeModal('approve-modal');
                    loadReports();
                } else {
                    showToast(data.error || 'Failed to approve', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }
        
        async function openRelease(reportId) {
            currentReportId = reportId;
            const report = reports.find(r => r.report_id === reportId);
            if (!report) return;
            
            // Get confirmation data
            try {
                const response = await fetch(`/api/admin/reports/${reportId}/release-confirm`, {
                    headers: getHeaders()
                });
                const data = await response.json();
                
                if (!response.ok) {
                    showToast(data.error || 'Cannot release this report', 'error');
                    return;
                }
                
                document.getElementById('release-client-id').textContent = data.client_id;
                document.getElementById('release-report-title').textContent = data.title || 'Untitled';
                document.getElementById('release-hash').textContent = (data.hash || '').substring(0, 16) + '...';
                document.getElementById('release-confirmation-string').textContent = data.confirmation_string;
                document.getElementById('release-confirmation-input').value = '';
                document.getElementById('release-confirm-btn').disabled = true;
                
                openModal('release-modal');
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }
        
        // Enable release button only when confirmation matches
        document.getElementById('release-confirmation-input').addEventListener('input', (e) => {
            const expected = document.getElementById('release-confirmation-string').textContent;
            const btn = document.getElementById('release-confirm-btn');
            btn.disabled = e.target.value.trim() !== expected;
        });
        
        async function confirmRelease() {
            if (!currentReportId) return;
            
            const confirmation = document.getElementById('release-confirmation-input').value;
            
            try {
                const response = await fetch(`/api/admin/reports/${currentReportId}/release`, {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify({ confirmation })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showToast('🚀 Report released to client!', 'success');
                    closeModal('release-modal');
                    loadReports();
                } else {
                    showToast(data.error || 'Failed to release', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }
        
        async function revokeReport(reportId) {
            const reason = prompt('Reason for revoking this report:');
            if (!reason) return;
            
            try {
                const response = await fetch(`/api/admin/reports/${reportId}/revoke`, {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify({ reason })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showToast('Report access revoked', 'success');
                    loadReports();
                } else {
                    showToast(data.error || 'Failed to revoke', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }
        
        async function viewDetails(reportId) {
            try {
                const response = await fetch(`/api/admin/reports/${reportId}`, {
                    headers: getHeaders()
                });
                const data = await response.json();
                const report = data.report;
                const auditLog = data.audit_log || [];
                
                document.getElementById('details-content').innerHTML = `
                    <div class="confirmation-box">
                        <div class="label">Report ID</div>
                        <div class="value">${report.report_id}</div>
                    </div>
                    <div class="confirmation-box">
                        <div class="label">Client</div>
                        <div class="value">${report.client_id}</div>
                    </div>
                    <div class="confirmation-box">
                        <div class="label">Title</div>
                        <div class="value">${report.title || 'Untitled'}</div>
                    </div>
                    <div class="confirmation-box">
                        <div class="label">Status</div>
                        <div class="value"><span class="status-badge ${report.status.toLowerCase()}">${report.status}</span></div>
                    </div>
                    <div class="confirmation-box">
                        <div class="label">Hash</div>
                        <div class="value" style="font-size: 0.8rem; word-break: break-all;">${report.hash || 'N/A'}</div>
                    </div>
                    <div class="confirmation-box">
                        <div class="label">Notes</div>
                        <div class="value">${report.notes || 'None'}</div>
                    </div>
                    <h3 style="margin: 20px 0 12px; color: var(--muted);">Audit Log</h3>
                    <div style="max-height: 200px; overflow-y: auto;">
                        ${auditLog.length ? auditLog.map(entry => `
                            <div style="padding: 8px; border-bottom: 1px solid var(--border); font-size: 0.85rem;">
                                <strong>${entry.action}</strong> by ${entry.actor}
                                <span style="color: var(--muted); float: right;">${formatDate(entry.timestamp)}</span>
                            </div>
                        `).join('') : '<div style="color: var(--muted);">No audit entries</div>'}
                    </div>
                `;
                openModal('details-modal');
            } catch (err) {
                showToast('Error loading details', 'error');
            }
        }
        
        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 4000);
        }
        
        // Initial load
        loadReports();
        
        // Refresh every 30 seconds
        setInterval(loadReports, 30000);
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """Serve the dashboard HTML."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/admin')
def admin_dashboard():
    """Serve the admin dashboard HTML."""
    return render_template_string(ADMIN_DASHBOARD_HTML)


@app.route('/client')
def client_portal():
    """Serve the client self-service portal."""
    return render_template_string(CLIENT_PORTAL_HTML)


@app.route('/admin/reports')
def admin_reports():
    """Serve the admin reports management page."""
    return render_template_string(ADMIN_REPORTS_HTML)


@app.route('/api/admin/clients')
def list_clients():
    """List all clients with their scan counts.
    
    Requires admin JWT or DASHBOARD_TOKEN.
    """
    # Check auth
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin = False
    
    if JWT_AUTH_AVAILABLE:
        try:
            claims = get_jwt_auth().validate_token(token)
            if claims and claims.is_admin:
                is_admin = True
        except:
            pass
    
    if not is_admin and token != DASHBOARD_TOKEN:
        abort(401, 'Admin access required')
    
    # Group scans by client_id
    clients = {}
    for org_id, scan in active_scans.items():
        client_id = scan.get('client_id') or 'default'
        if client_id not in clients:
            clients[client_id] = {
                'client_id': client_id,
                'active_scans': 0,
                'scans': [],
            }
        clients[client_id]['active_scans'] += 1
        clients[client_id]['scans'].append({
            'org_id': org_id,
            'scan_id': scan.get('scan_id'),
            'target': scan.get('target'),
            'status': scan.get('status'),
            'started_at': scan.get('started_at'),
        })
    
    return jsonify({
        'clients': list(clients.values()),
        'total_clients': len(clients),
        'total_scans': len(active_scans),
    })


@app.route('/api/admin/all-scans')
def list_all_scans():
    """List all active scans across all clients.
    
    Requires admin JWT or DASHBOARD_TOKEN.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin = False
    
    if JWT_AUTH_AVAILABLE:
        try:
            claims = get_jwt_auth().validate_token(token)
            if claims and claims.is_admin:
                is_admin = True
        except:
            pass
    
    if not is_admin and token != DASHBOARD_TOKEN:
        abort(401, 'Admin access required')
    
    scans = []
    for org_id, scan in active_scans.items():
        scans.append({
            'org_id': org_id,
            'client_id': scan.get('client_id') or 'default',
            'scan_id': scan.get('scan_id'),
            'target': scan.get('target'),
            'status': scan.get('status'),
            'started_at': scan.get('started_at'),
            'pid': scan.get('pid'),
        })
    
    # Sort by started_at descending
    scans.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    
    return jsonify({
        'scans': scans,
        'total': len(scans),
    })


@app.route('/api/admin/switch-client/<client_id>')
def switch_to_client(client_id: str):
    """Get a client-scoped JWT token for viewing their dashboard.
    
    Allows admin to impersonate a client's view.
    Requires admin JWT or DASHBOARD_TOKEN.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin = False
    
    if JWT_AUTH_AVAILABLE:
        try:
            claims = get_jwt_auth().validate_token(token)
            if claims and claims.is_admin:
                is_admin = True
        except:
            pass
    
    if not is_admin and token != DASHBOARD_TOKEN:
        abort(401, 'Admin access required')
    
    if not JWT_AUTH_AVAILABLE:
        abort(501, 'JWT auth not available')
    
    # Generate a client-scoped viewer token
    auth = get_jwt_auth()
    from datetime import timedelta
    client_token = auth.create_token(
        client_id=client_id,
        role='viewer',
        expires_in=timedelta(hours=2),
    )
    
    return jsonify({
        'client_id': client_id,
        'token': client_token,
        'dashboard_url': f"/?token={client_token}",
    })


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
    
    # Multi-tenant: Broadcast to appropriate room(s)
    client_id = payload.get('client_id') or data.get('client_id')
    
    if client_id:
        # Emit to client-specific room
        socketio.emit('scan_event', event_dict, room=f"client_{client_id}")
    
    # Always emit to admin and legacy rooms
    socketio.emit('scan_event', event_dict, room="admin")
    socketio.emit('scan_event', event_dict, room="all")
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
    client_id = data.get('client_id')  # Multi-tenant support
    
    scan_data = {
        'scan_id': scan_id,
        'org_id': org_id,
        'pid': pid,
        'target': target,
        'started_at': datetime.now().isoformat(),
        'status': 'running',
        'client_id': client_id,  # Multi-tenant
    }
    
    active_scans[org_id] = scan_data
    
    # Persist to storage
    if storage:
        try:
            storage.save_scan(scan_id, scan_data)
        except Exception as e:
            print(f"[Dashboard] Failed to persist scan: {e}")
    
    # Multi-tenant: Broadcast scan start to appropriate rooms
    emit_data = {'org_id': org_id, 'scan': active_scans[org_id]}
    if client_id:
        socketio.emit('scan_registered', emit_data, room=f"client_{client_id}")
    socketio.emit('scan_registered', emit_data, room="admin")
    socketio.emit('scan_registered', emit_data, room="all")
    
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
    
    # Get client_id for room routing
    client_id = active_scans.get(org_id, {}).get('client_id')
    
    # Broadcast kill event to appropriate rooms
    kill_event_data = {
        'org_id': org_id,
        'reason': reason,
        'message': f'Kill signal sent for {org_id}'
    }
    if client_id:
        socketio.emit('scan_killed', kill_event_data, room=f"client_{client_id}")
    socketio.emit('scan_killed', kill_event_data, room="admin")
    socketio.emit('scan_killed', kill_event_data, room="all")
    
    # Also emit as scan event for the event stream
    stream = get_event_stream()
    event = stream.emit(EventType.SCAN_COMPLETE, {
        'status': 'killed',
        'reason': reason,
        'org_id': org_id,
        'client_id': client_id
    })
    event_dict = event.to_dict()
    if client_id:
        socketio.emit('scan_event', event_dict, room=f"client_{client_id}")
    socketio.emit('scan_event', event_dict, room="admin")
    socketio.emit('scan_event', event_dict, room="all")
    
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


# ---------- JWT Auth Endpoints ----------

@app.route('/api/auth/token', methods=['POST'])
def create_jwt_token():
    """Create a JWT token for client access.
    
    Requires admin token (DASHBOARD_TOKEN) to issue new tokens.
    
    Request body:
        client_id: str - Client identifier
        role: str - 'admin', 'client', or 'viewer' (default: 'client')
        expires_in_hours: int - Token expiry in hours (optional)
    
    Returns:
        token: str - JWT token
        expires_at: str - Token expiry timestamp
    """
    # Require admin auth to issue tokens
    admin_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if admin_token != DASHBOARD_TOKEN:
        abort(401, 'Admin token required to issue JWT tokens')
    
    if not JWT_AUTH_AVAILABLE:
        abort(501, 'JWT auth not available')
    
    data = request.get_json()
    if not data or not data.get('client_id'):
        abort(400, 'client_id required')
    
    client_id = data['client_id']
    role = data.get('role', 'client')
    
    if role not in ['admin', 'client', 'viewer']:
        abort(400, 'Invalid role. Must be admin, client, or viewer')
    
    # Custom expiry
    from datetime import timedelta
    expires_in = None
    if data.get('expires_in_hours'):
        expires_in = timedelta(hours=int(data['expires_in_hours']))
    
    auth = get_jwt_auth()
    token = auth.create_token(
        client_id=client_id,
        role=role,
        expires_in=expires_in,
    )
    
    # Decode to get expiry
    claims = auth.validate_token(token)
    
    return jsonify({
        'token': token,
        'client_id': client_id,
        'role': role,
        'expires_at': claims.exp.isoformat() if claims else None,
    })


@app.route('/api/auth/validate', methods=['GET'])
def validate_jwt_token():
    """Validate a JWT token and return claims.
    
    Pass token via Authorization: Bearer <token> header or ?token= param.
    """
    if not JWT_AUTH_AVAILABLE:
        abort(501, 'JWT auth not available')
    
    auth = get_jwt_auth()
    token = auth.extract_token_from_request()
    
    if not token:
        return jsonify({'valid': False, 'error': 'No token provided'}), 401
    
    claims = auth.validate_token(token)
    
    if not claims:
        return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 401
    
    return jsonify({
        'valid': True,
        'client_id': claims.client_id,
        'role': claims.role,
        'is_admin': claims.is_admin,
        'permissions': claims.permissions,
        'expires_at': claims.exp.isoformat(),
    })


# =============================================================================
# Report Release Workflow Endpoints
# =============================================================================

@app.route('/api/admin/reports', methods=['GET'])
def list_admin_reports():
    """List all reports (admin only).
    
    Query params:
    - status: Filter by status (STAGED, APPROVED, RELEASED, REVOKED)
    - client_id: Filter by client
    - limit: Max results (default 50)
    """
    # Check auth
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    status = request.args.get('status')
    client_id = request.args.get('client_id')
    limit = int(request.args.get('limit', 50))
    
    reports = storage.list_reports(client_id=client_id, status=status, limit=limit)
    
    # Group by status for summary
    status_counts = {}
    for r in storage.list_reports(limit=1000):
        s = r.get('status', 'UNKNOWN')
        status_counts[s] = status_counts.get(s, 0) + 1
    
    return jsonify({
        'reports': reports,
        'total': len(reports),
        'status_counts': status_counts
    })


@app.route('/api/admin/reports/<report_id>', methods=['GET'])
def get_admin_report(report_id):
    """Get report details including audit log (admin only)."""
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    audit_log = storage.get_report_audit_log(report_id)
    
    return jsonify({
        'report': report,
        'audit_log': audit_log
    })


@app.route('/api/admin/reports', methods=['POST'])
def create_report():
    """Create a new report in STAGED status (admin only).
    
    Body:
    - client_id: Required
    - scan_id: Required
    - title: Optional
    - artifact_paths: Optional dict with pdf/md/json paths
    - findings_count: Optional
    - notes: Optional
    """
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    data = request.get_json() or {}
    
    if not data.get('client_id'):
        return jsonify({'error': 'client_id is required'}), 400
    if not data.get('scan_id'):
        return jsonify({'error': 'scan_id is required'}), 400
    
    # Get actor from JWT or fallback
    actor = 'admin'
    if JWT_AUTH_AVAILABLE:
        try:
            auth = get_jwt_auth()
            token = auth.extract_token_from_request()
            if token:
                claims = auth.validate_token(token)
                if claims:
                    actor = claims.client_id
        except:
            pass
    
    data['created_by'] = actor
    data['ip_address'] = request.remote_addr
    
    try:
        report_id = storage.create_report(data)
        report = storage.get_report(report_id)
        
        return jsonify({
            'status': 'ok',
            'report_id': report_id,
            'report': report
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/admin/reports/<report_id>/approve', methods=['POST'])
def approve_report(report_id):
    """Approve a STAGED report (admin only).
    
    Body:
    - notes: Optional approval notes
    """
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    if report.get('status') != 'STAGED':
        return jsonify({'error': f"Cannot approve report in {report.get('status')} status"}), 400
    
    data = request.get_json() or {}
    actor = _get_actor_from_request()
    
    try:
        storage.update_report_status(
            report_id=report_id,
            new_status='APPROVED',
            actor=actor,
            ip_address=request.remote_addr,
            notes=data.get('notes')
        )
        
        updated = storage.get_report(report_id)
        return jsonify({
            'status': 'ok',
            'message': 'Report approved',
            'report': updated
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/admin/reports/<report_id>/release-confirm', methods=['GET'])
def get_release_confirmation(report_id):
    """Get release confirmation data (admin only).
    
    Returns the confirmation string that must be typed to release.
    """
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    if report.get('status') != 'APPROVED':
        return jsonify({'error': f"Cannot release report in {report.get('status')} status. Must be APPROVED first."}), 400
    
    confirmation = storage.get_report_release_confirmation(report_id)
    return jsonify(confirmation)


@app.route('/api/admin/reports/<report_id>/release', methods=['POST'])
def release_report(report_id):
    """Release an APPROVED report to client (requires confirmation).
    
    Body:
    - confirmation: Required - typed confirmation string (e.g. "RELEASE acme_corp 1")
    """
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    if report.get('status') != 'APPROVED':
        return jsonify({'error': f"Cannot release report in {report.get('status')} status. Must be APPROVED first."}), 400
    
    data = request.get_json() or {}
    confirmation = data.get('confirmation')
    
    if not confirmation:
        return jsonify({'error': 'Confirmation string required'}), 400
    
    # Verify confirmation
    if not storage.verify_release_confirmation(report_id, confirmation):
        expected = storage.get_report_release_confirmation(report_id)
        return jsonify({
            'error': 'Confirmation string does not match',
            'expected_format': 'RELEASE <client_slug> <version>',
            'hint': f"Expected: {expected.get('confirmation_string')}" if expected else None
        }), 400
    
    actor = _get_actor_from_request()
    
    # Optional: Check two-person rule
    two_person_rule = os.getenv('REPORT_TWO_PERSON_RULE', 'false').lower() == 'true'
    if two_person_rule and report.get('approved_by') == actor:
        return jsonify({
            'error': 'Two-person rule: approver cannot release. A different admin must release.',
            'approved_by': report.get('approved_by')
        }), 403
    
    try:
        storage.update_report_status(
            report_id=report_id,
            new_status='RELEASED',
            actor=actor,
            ip_address=request.remote_addr,
            notes=data.get('notes')
        )
        
        updated = storage.get_report(report_id)
        return jsonify({
            'status': 'ok',
            'message': 'Report released to client',
            'report': updated
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/admin/reports/<report_id>/revoke', methods=['POST'])
def revoke_report(report_id):
    """Revoke a RELEASED report (admin only).
    
    Body:
    - reason: Required - reason for revocation
    """
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    if report.get('status') != 'RELEASED':
        return jsonify({'error': f"Cannot revoke report in {report.get('status')} status. Must be RELEASED."}), 400
    
    data = request.get_json() or {}
    reason = data.get('reason')
    
    if not reason:
        return jsonify({'error': 'Reason for revocation is required'}), 400
    
    actor = _get_actor_from_request()
    
    try:
        storage.update_report_status(
            report_id=report_id,
            new_status='REVOKED',
            actor=actor,
            ip_address=request.remote_addr,
            notes=f"Revoked: {reason}"
        )
        
        updated = storage.get_report(report_id)
        return jsonify({
            'status': 'ok',
            'message': 'Report access revoked',
            'report': updated
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/admin/reports/<report_id>/audit', methods=['GET'])
def get_report_audit(report_id):
    """Get audit log for a report (admin only)."""
    if not check_auth():
        abort(401)
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    audit_log = storage.get_report_audit_log(report_id)
    return jsonify({
        'report_id': report_id,
        'audit_log': audit_log,
        'total': len(audit_log)
    })


# =============================================================================
# Client Portal Report Endpoints
# =============================================================================

@app.route('/api/portal/reports', methods=['GET'])
def list_client_reports():
    """List released reports for the authenticated client."""
    # Get client_id from JWT
    client_id = None
    if JWT_AUTH_AVAILABLE:
        try:
            auth = get_jwt_auth()
            token = auth.extract_token_from_request()
            if token:
                claims = auth.validate_token(token)
                if claims:
                    client_id = claims.client_id
        except:
            pass
    
    if not client_id:
        return jsonify({'error': 'Client authentication required'}), 401
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    # Only return RELEASED reports for this client
    reports = storage.list_reports(client_id=client_id, status='RELEASED')
    
    # Strip internal fields for client view
    client_reports = []
    for r in reports:
        client_reports.append({
            'report_id': r.get('report_id'),
            'title': r.get('title'),
            'scan_id': r.get('scan_id'),
            'version': r.get('version'),
            'findings_count': r.get('findings_count'),
            'released_at': r.get('released_at'),
            'hash': r.get('hash'),
        })
    
    return jsonify({
        'reports': client_reports,
        'total': len(client_reports)
    })


@app.route('/api/portal/reports/<report_id>', methods=['GET'])
def get_client_report(report_id):
    """Get a specific released report for the authenticated client."""
    client_id = _get_client_id_from_request()
    
    if not client_id:
        return jsonify({'error': 'Client authentication required'}), 401
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Security check: verify client_id match AND status is RELEASED
    if report.get('client_id') != client_id:
        return jsonify({'error': 'Access denied'}), 403
    
    if report.get('status') != 'RELEASED':
        return jsonify({'error': 'Report not available'}), 404
    
    # Log the access
    actor = _get_actor_from_request()
    storage.log_report_action(
        report_id=report_id,
        action='viewed',
        actor=actor,
        ip_address=request.remote_addr,
        details={'client_id': client_id}
    )
    
    # Return client-safe view
    return jsonify({
        'report_id': report.get('report_id'),
        'title': report.get('title'),
        'scan_id': report.get('scan_id'),
        'version': report.get('version'),
        'findings_count': report.get('findings_count'),
        'released_at': report.get('released_at'),
        'hash': report.get('hash'),
        'artifact_paths': report.get('artifact_paths'),  # For download links
    })


@app.route('/api/portal/reports/<report_id>/download/<artifact_type>', methods=['GET'])
def download_report(report_id, artifact_type):
    """Download a report artifact (pdf, md, json).
    
    Security: Re-verifies auth and client_id on every download request.
    """
    client_id = _get_client_id_from_request()
    
    if not client_id:
        return jsonify({'error': 'Client authentication required'}), 401
    
    if not storage:
        return jsonify({'error': 'Storage not available'}), 503
    
    report = storage.get_report(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Security checks
    if report.get('client_id') != client_id:
        return jsonify({'error': 'Access denied'}), 403
    
    if report.get('status') != 'RELEASED':
        return jsonify({'error': 'Report not available'}), 404
    
    artifact_paths = report.get('artifact_paths', {})
    if artifact_type not in artifact_paths:
        return jsonify({'error': f'Artifact type {artifact_type} not available'}), 404
    
    # Log the download
    actor = _get_actor_from_request()
    storage.log_report_action(
        report_id=report_id,
        action='downloaded',
        actor=actor,
        ip_address=request.remote_addr,
        details={'client_id': client_id, 'artifact_type': artifact_type}
    )
    
    # Return download info (actual file serving depends on your storage backend)
    # For now, return the path - implement actual file streaming based on your setup
    artifact_path = artifact_paths[artifact_type]
    
    # If using local files, you could stream the file:
    # from flask import send_file
    # return send_file(artifact_path, as_attachment=True)
    
    # For now, return signed URL info (implement actual signing based on your needs)
    return jsonify({
        'status': 'ok',
        'artifact_type': artifact_type,
        'artifact_path': artifact_path,
        'hash': report.get('hash'),
        'message': 'Implement file streaming based on your storage backend'
    })


def _get_actor_from_request() -> str:
    """Extract actor (username/client_id) from request."""
    if JWT_AUTH_AVAILABLE:
        try:
            auth = get_jwt_auth()
            token = auth.extract_token_from_request()
            if token:
                claims = auth.validate_token(token)
                if claims:
                    return claims.client_id
        except:
            pass
    return 'admin'


def _get_client_id_from_request() -> Optional[str]:
    """Extract client_id from JWT token."""
    if JWT_AUTH_AVAILABLE:
        try:
            auth = get_jwt_auth()
            token = auth.extract_token_from_request()
            if token:
                claims = auth.validate_token(token)
                if claims:
                    return claims.client_id
        except:
            pass
    return None


@socketio.on('connect')
def handle_connect(auth=None):
    """Handle WebSocket connection with token auth and room assignment.
    
    Authentication methods (checked in order):
    1. JWT token (preferred for multi-tenant)
    2. Simple DASHBOARD_TOKEN (legacy/backward compatible)
    
    Multi-tenant support:
    - JWT with client_id claim: Auto-join client-specific room
    - client_id param: Join client-specific room for isolated events
    - admin role in JWT: Join 'admin' room to see all events
    - No client_id: Legacy mode, see all events (backward compatible)
    """
    # Debug: log what we receive
    print(f"[DEBUG] Connect attempt - auth={auth}, args={dict(request.args)}", flush=True)
    
    token = request.args.get('token') or (auth.get('token') if auth else None)
    
    # Try JWT auth first
    client_id = None
    is_admin = False
    jwt_validated = False
    
    if JWT_AUTH_AVAILABLE and token:
        try:
            jwt_auth = get_jwt_auth()
            claims = jwt_auth.validate_token(token)
            if claims:
                jwt_validated = True
                client_id = claims.client_id
                is_admin = claims.is_admin
                print(f"[DEBUG] JWT valid - client_id={client_id}, role={claims.role}", flush=True)
        except Exception as e:
            print(f"[DEBUG] JWT validation error: {e}", flush=True)
    
    # Fall back to simple token auth if JWT didn't validate
    if not jwt_validated:
        print(f"[DEBUG] Trying simple token auth, expected={DASHBOARD_TOKEN!r}", flush=True)
        if token != DASHBOARD_TOKEN:
            print(f"[DEBUG] Token mismatch - rejecting connection", flush=True)
            return False  # Reject connection
        print(f"[DEBUG] Simple token valid - accepting connection", flush=True)
        
        # Get client_id/admin from params for simple token auth
        client_id = request.args.get('client_id') or (auth.get('client_id') if auth else None)
        is_admin = request.args.get('admin') == 'true' or (auth.get('admin') if auth else False)
    
    if client_id:
        # Client-specific room
        join_room(f"client_{client_id}")
        print(f"[DEBUG] Joined room: client_{client_id}", flush=True)
    
    if is_admin:
        # Admin room sees all events
        join_room("admin")
        print(f"[DEBUG] Joined room: admin", flush=True)
    
    if not client_id and not is_admin:
        # Legacy mode: join 'all' room for backward compatibility
        join_room("all")
        print(f"[DEBUG] Joined room: all (legacy mode)", flush=True)
    
    try:
        # Send current stats on connect
        emit('stats_update', get_event_stream().get_stats())
        
        # Send active scans (filtered by client_id if provided)
        if client_id:
            client_scans = {k: v for k, v in active_scans.items() 
                          if v.get('client_id') == client_id}
            emit('active_scans', client_scans)
        else:
            emit('active_scans', active_scans)
        
        # Send recent events (filtered by client_id if provided)
        for event in get_event_stream().get_recent_events(20):
            event_dict = event.to_dict()
            if client_id:
                # Only send events for this client
                if event_dict.get('client_id') == client_id:
                    emit('scan_event', event_dict)
            else:
                emit('scan_event', event_dict)
    except Exception as e:
        print(f"[DEBUG] Error in connect handler: {e}", flush=True)


def broadcast_event(event: ScanEvent):
    """Broadcast an event to appropriate room(s).
    
    Multi-tenant routing:
    - If event has client_id, emit to client_{client_id} room
    - Always emit to 'admin' room (admins see all)
    - Always emit to 'all' room (legacy mode clients)
    """
    event_dict = event.to_dict()
    client_id = event_dict.get('client_id')
    
    # Emit to client-specific room if client_id present
    if client_id:
        socketio.emit('scan_event', event_dict, room=f"client_{client_id}")
    
    # Always emit to admin room
    socketio.emit('scan_event', event_dict, room="admin")
    
    # Always emit to 'all' room for legacy clients
    socketio.emit('scan_event', event_dict, room="all")
    
    # Broadcast stats to everyone
    stats = get_event_stream().get_stats()
    socketio.emit('stats_update', stats)


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
