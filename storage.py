#!/usr/bin/env python3
"""Persistence Layer for Agentic Security Dashboard

Provides storage backends for scan state, events, findings, and reports.
Supports SQLite (default for Fly.io) and in-memory (development).

Usage:
    from storage import get_storage
    storage = get_storage()
    
    # Save scan state
    storage.save_scan(scan_id, scan_data)
    
    # Get scan history
    scans = storage.list_scans(limit=50)
    
    # Save events
    storage.save_event(event_data)
    
    # Report Release Workflow
    storage.create_report(report_data)
    storage.list_reports(client_id, status)
    storage.update_report_status(report_id, status, actor, notes)
"""

import os
import json
import sqlite3
import threading
import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import contextmanager
from enum import Enum


class ReportStatus(str, Enum):
    """Report release workflow states."""
    STAGED = "STAGED"       # Generated, admin-only visible
    APPROVED = "APPROVED"   # Admin verified, ready for release
    RELEASED = "RELEASED"   # Client can access
    REVOKED = "REVOKED"     # Access removed


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def initialize(self):
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    def save_scan(self, scan_id: str, data: Dict[str, Any]) -> bool:
        """Save or update a scan."""
        pass
    
    @abstractmethod
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a scan by ID."""
        pass
    
    @abstractmethod
    def list_scans(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent scans."""
        pass
    
    @abstractmethod
    def save_event(self, event: Dict[str, Any]) -> bool:
        """Save an event."""
        pass
    
    @abstractmethod
    def get_events(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events, optionally filtered by scan_id."""
        pass
    
    @abstractmethod
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        """Save a finding."""
        pass
    
    @abstractmethod
    def get_findings(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get findings, optionally filtered by scan_id."""
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        pass
    
    @abstractmethod
    def update_stats(self, stats: Dict[str, Any]) -> bool:
        """Update dashboard statistics."""
        pass
    
    # Report Release Workflow Methods
    
    @abstractmethod
    def create_report(self, report: Dict[str, Any]) -> str:
        """Create a new report in STAGED status. Returns report_id."""
        pass
    
    @abstractmethod
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a report by ID."""
        pass
    
    @abstractmethod
    def list_reports(
        self, 
        client_id: Optional[str] = None, 
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List reports, optionally filtered by client_id and/or status."""
        pass
    
    @abstractmethod
    def update_report_status(
        self,
        report_id: str,
        new_status: str,
        actor: str,
        ip_address: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """Update report status and log the action."""
        pass
    
    @abstractmethod
    def get_report_audit_log(self, report_id: str) -> List[Dict[str, Any]]:
        """Get audit log entries for a report."""
        pass
    
    @abstractmethod
    def log_report_action(
        self,
        report_id: str,
        action: str,
        actor: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Log an action on a report for audit trail."""
        pass


class SQLiteStorage(StorageBackend):
    """SQLite-based persistent storage for Fly.io deployment."""
    
    def __init__(self, db_path: str = "/data/dashboard.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
    
    @contextmanager
    def _get_conn(self):
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None  # autocommit
            )
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except Exception as e:
            print(f"[Storage] Database error: {e}")
            raise
    
    def initialize(self):
        """Create database tables if they don't exist."""
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_conn() as conn:
            conn.executescript("""
                -- Scans table
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    org_id TEXT,
                    target TEXT,
                    status TEXT DEFAULT 'running',
                    started_at TEXT,
                    completed_at TEXT,
                    progress_pct REAL DEFAULT 0,
                    current_phase TEXT,
                    finding_count INTEGER DEFAULT 0,
                    data JSON,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
                
                -- Events table
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    event_type TEXT,
                    timestamp TEXT,
                    data JSON,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
                
                -- Findings table
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    title TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'candidate',
                    cwe TEXT,
                    endpoint TEXT,
                    data JSON,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                
                -- Stats table (single row for global stats)
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total_scans INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    data JSON,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                INSERT OR IGNORE INTO stats (id) VALUES (1);
                
                -- Reports table (Report Release Workflow)
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    status TEXT DEFAULT 'STAGED' CHECK (status IN ('STAGED', 'APPROVED', 'RELEASED', 'REVOKED')),
                    version INTEGER DEFAULT 1,
                    title TEXT,
                    artifact_paths JSON,
                    hash TEXT,
                    findings_count INTEGER DEFAULT 0,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    approved_at TEXT,
                    released_at TEXT,
                    revoked_at TEXT,
                    approved_by TEXT,
                    released_by TEXT,
                    revoked_by TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_reports_client ON reports(client_id);
                CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
                CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
                
                -- Report Audit Log
                CREATE TABLE IF NOT EXISTS report_audit_log (
                    id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    ip_address TEXT,
                    details JSON,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_audit_report ON report_audit_log(report_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON report_audit_log(timestamp DESC);
            """)
        print(f"[Storage] SQLite database initialized at {self.db_path}")
    
    def save_scan(self, scan_id: str, data: Dict[str, Any]) -> bool:
        """Save or update a scan."""
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO scans (scan_id, org_id, target, status, started_at, progress_pct, current_phase, finding_count, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status = excluded.status,
                    progress_pct = excluded.progress_pct,
                    current_phase = excluded.current_phase,
                    finding_count = excluded.finding_count,
                    data = excluded.data,
                    completed_at = CASE WHEN excluded.status IN ('complete', 'killed', 'error') THEN CURRENT_TIMESTAMP ELSE completed_at END
            """, (
                scan_id,
                data.get('org_id', 'default'),
                data.get('target', ''),
                data.get('status', 'running'),
                data.get('started_at', datetime.utcnow().isoformat()),
                data.get('progress_pct', 0),
                data.get('current_phase', ''),
                data.get('finding_count', 0),
                json.dumps(data)
            ))
        return True
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a scan by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row:
                return dict(row)
        return None
    
    def list_scans(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent scans."""
        with self._get_conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            return [dict(row) for row in rows]
    
    def save_event(self, event: Dict[str, Any]) -> bool:
        """Save an event."""
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO events (event_id, scan_id, event_type, timestamp, data)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event.get('event_id', f"evt_{int(datetime.utcnow().timestamp() * 1000)}"),
                event.get('scan_id', 'default'),
                event.get('event_type', 'unknown'),
                event.get('timestamp', datetime.utcnow().isoformat()),
                json.dumps(event.get('data', {}))
            ))
        return True
    
    def get_events(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events."""
        with self._get_conn() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM events WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
                    (scan_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            
            events = []
            for row in rows:
                event = dict(row)
                if event.get('data'):
                    try:
                        event['data'] = json.loads(event['data'])
                    except:
                        pass
                events.append(event)
            return events
    
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        """Save a finding."""
        finding_id = finding.get('finding_id') or finding.get('id') or f"fnd_{int(datetime.utcnow().timestamp() * 1000)}"
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO findings (finding_id, scan_id, title, severity, status, cwe, endpoint, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                finding.get('scan_id', 'default'),
                finding.get('title', 'Unknown Finding'),
                finding.get('severity', 'medium'),
                finding.get('status', 'candidate'),
                finding.get('cwe', ''),
                finding.get('endpoint', finding.get('url', '')),
                json.dumps(finding)
            ))
            
            # Update stats
            self._increment_finding_count(finding.get('severity', 'medium'))
        return True
    
    def _increment_finding_count(self, severity: str):
        """Increment the finding count for a severity level."""
        severity_col = f"{severity.lower()}_count"
        if severity_col not in ('critical_count', 'high_count', 'medium_count', 'low_count'):
            severity_col = 'medium_count'
        
        with self._get_conn() as conn:
            conn.execute(f"""
                UPDATE stats SET 
                    total_findings = total_findings + 1,
                    {severity_col} = {severity_col} + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """)
    
    def get_findings(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get findings."""
        with self._get_conn() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
                    (scan_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            
            findings = []
            for row in rows:
                finding = dict(row)
                if finding.get('data'):
                    try:
                        finding['data'] = json.loads(finding['data'])
                    except:
                        pass
                findings.append(finding)
            return findings
    
    def get_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
            if row:
                stats = dict(row)
                if stats.get('data'):
                    try:
                        extra = json.loads(stats['data'])
                        stats.update(extra)
                    except:
                        pass
                return stats
        return {}
    
    def update_stats(self, stats: Dict[str, Any]) -> bool:
        """Update dashboard statistics."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE stats SET 
                    total_scans = ?,
                    total_findings = ?,
                    critical_count = ?,
                    high_count = ?,
                    medium_count = ?,
                    low_count = ?,
                    data = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (
                stats.get('total_scans', 0),
                stats.get('total_findings', 0),
                stats.get('critical_count', 0),
                stats.get('high_count', 0),
                stats.get('medium_count', 0),
                stats.get('low_count', 0),
                json.dumps(stats)
            ))
        return True
    
    def get_active_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get currently running scans."""
        scans = self.list_scans(limit=50, status='running')
        return {s['scan_id']: json.loads(s['data']) if isinstance(s.get('data'), str) else s.get('data', s) for s in scans}
    
    def mark_scan_complete(self, scan_id: str, status: str = 'complete'):
        """Mark a scan as complete."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE scans SET 
                    status = ?,
                    completed_at = CURRENT_TIMESTAMP
                WHERE scan_id = ?
            """, (status, scan_id))
            
            # Increment total scans
            conn.execute("""
                UPDATE stats SET 
                    total_scans = total_scans + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """)
    
    # =========================================================================
    # Report Release Workflow Implementation
    # =========================================================================
    
    def create_report(self, report: Dict[str, Any]) -> str:
        """Create a new report in STAGED status."""
        report_id = report.get('report_id') or f"rpt_{uuid.uuid4().hex[:12]}"
        client_id = report.get('client_id')
        
        if not client_id:
            raise ValueError("client_id is required for report creation")
        
        # Calculate hash of artifact if provided
        artifact_paths = report.get('artifact_paths', {})
        report_hash = report.get('hash')
        if not report_hash and artifact_paths.get('pdf'):
            # Generate placeholder hash from metadata
            hash_input = f"{client_id}:{report.get('scan_id')}:{datetime.utcnow().isoformat()}"
            report_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO reports (
                    report_id, client_id, scan_id, status, version, title,
                    artifact_paths, hash, findings_count, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                client_id,
                report.get('scan_id', ''),
                ReportStatus.STAGED.value,
                report.get('version', 1),
                report.get('title', f"Security Report - {client_id}"),
                json.dumps(artifact_paths),
                report_hash,
                report.get('findings_count', 0),
                report.get('notes', '')
            ))
            
            # Log the creation action
            self.log_report_action(
                report_id=report_id,
                action='created',
                actor=report.get('created_by', 'system'),
                ip_address=report.get('ip_address'),
                details={'client_id': client_id, 'scan_id': report.get('scan_id')}
            )
        
        return report_id
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a report by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE report_id = ?", (report_id,)
            ).fetchone()
            if row:
                report = dict(row)
                if report.get('artifact_paths'):
                    try:
                        report['artifact_paths'] = json.loads(report['artifact_paths'])
                    except:
                        pass
                return report
        return None
    
    def list_reports(
        self,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List reports, optionally filtered by client_id and/or status."""
        with self._get_conn() as conn:
            query = "SELECT * FROM reports WHERE 1=1"
            params = []
            
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            
            reports = []
            for row in rows:
                report = dict(row)
                if report.get('artifact_paths'):
                    try:
                        report['artifact_paths'] = json.loads(report['artifact_paths'])
                    except:
                        pass
                reports.append(report)
            return reports
    
    def update_report_status(
        self,
        report_id: str,
        new_status: str,
        actor: str,
        ip_address: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """Update report status and log the action."""
        # Validate status
        try:
            status_enum = ReportStatus(new_status)
        except ValueError:
            raise ValueError(f"Invalid status: {new_status}")
        
        # Get current report to validate transition
        report = self.get_report(report_id)
        if not report:
            return False
        
        current_status = report.get('status')
        
        # Validate state transitions
        valid_transitions = {
            ReportStatus.STAGED.value: [ReportStatus.APPROVED.value],
            ReportStatus.APPROVED.value: [ReportStatus.RELEASED.value, ReportStatus.STAGED.value],
            ReportStatus.RELEASED.value: [ReportStatus.REVOKED.value],
            ReportStatus.REVOKED.value: [ReportStatus.RELEASED.value],  # Allow re-release
        }
        
        if new_status not in valid_transitions.get(current_status, []):
            raise ValueError(f"Invalid transition from {current_status} to {new_status}")
        
        with self._get_conn() as conn:
            # Build update based on new status
            update_fields = ["status = ?"]
            params = [new_status]
            
            if notes:
                update_fields.append("notes = ?")
                params.append(notes)
            
            if new_status == ReportStatus.APPROVED.value:
                update_fields.append("approved_at = CURRENT_TIMESTAMP")
                update_fields.append("approved_by = ?")
                params.append(actor)
            elif new_status == ReportStatus.RELEASED.value:
                update_fields.append("released_at = CURRENT_TIMESTAMP")
                update_fields.append("released_by = ?")
                params.append(actor)
            elif new_status == ReportStatus.REVOKED.value:
                update_fields.append("revoked_at = CURRENT_TIMESTAMP")
                update_fields.append("revoked_by = ?")
                params.append(actor)
            
            params.append(report_id)
            
            conn.execute(
                f"UPDATE reports SET {', '.join(update_fields)} WHERE report_id = ?",
                params
            )
            
            # Log the action
            action_map = {
                ReportStatus.APPROVED.value: 'approved',
                ReportStatus.RELEASED.value: 'released',
                ReportStatus.REVOKED.value: 'revoked',
                ReportStatus.STAGED.value: 'returned_to_staged',
            }
            
            self.log_report_action(
                report_id=report_id,
                action=action_map.get(new_status, 'status_changed'),
                actor=actor,
                ip_address=ip_address,
                details={
                    'previous_status': current_status,
                    'new_status': new_status,
                    'notes': notes
                }
            )
        
        return True
    
    def get_report_audit_log(self, report_id: str) -> List[Dict[str, Any]]:
        """Get audit log entries for a report."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM report_audit_log WHERE report_id = ? ORDER BY timestamp DESC",
                (report_id,)
            ).fetchall()
            
            entries = []
            for row in rows:
                entry = dict(row)
                if entry.get('details'):
                    try:
                        entry['details'] = json.loads(entry['details'])
                    except:
                        pass
                entries.append(entry)
            return entries
    
    def log_report_action(
        self,
        report_id: str,
        action: str,
        actor: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Log an action on a report for audit trail."""
        log_id = f"log_{uuid.uuid4().hex[:12]}"
        
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO report_audit_log (id, report_id, action, actor, ip_address, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                log_id,
                report_id,
                action,
                actor,
                ip_address,
                json.dumps(details) if details else None
            ))
        
        return True
    
    def get_report_release_confirmation(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get data needed for release confirmation."""
        report = self.get_report(report_id)
        if not report:
            return None
        
        # Generate confirmation string
        client_slug = report['client_id'].replace(' ', '_').lower()
        version = report.get('version', 1)
        confirmation_string = f"RELEASE {client_slug} {version}"
        
        return {
            'report_id': report_id,
            'client_id': report['client_id'],
            'client_slug': client_slug,
            'version': version,
            'hash': report.get('hash'),
            'title': report.get('title'),
            'findings_count': report.get('findings_count', 0),
            'confirmation_string': confirmation_string
        }
    
    def verify_release_confirmation(self, report_id: str, confirmation: str) -> bool:
        """Verify the typed confirmation string matches the expected format."""
        expected = self.get_report_release_confirmation(report_id)
        if not expected:
            return False
        return confirmation.strip() == expected['confirmation_string']


class MemoryStorage(StorageBackend):
    """In-memory storage for development/testing."""
    
    def __init__(self):
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.report_audit_log: List[Dict[str, Any]] = []
        self.stats: Dict[str, Any] = {
            'total_scans': 0,
            'total_findings': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
        }
        self._lock = threading.Lock()
    
    def initialize(self):
        print("[Storage] In-memory storage initialized (data will not persist)")
    
    def save_scan(self, scan_id: str, data: Dict[str, Any]) -> bool:
        with self._lock:
            self.scans[scan_id] = {**data, 'scan_id': scan_id}
        return True
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self.scans.get(scan_id)
    
    def list_scans(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        scans = list(self.scans.values())
        if status:
            scans = [s for s in scans if s.get('status') == status]
        return sorted(scans, key=lambda x: x.get('started_at', ''), reverse=True)[:limit]
    
    def save_event(self, event: Dict[str, Any]) -> bool:
        with self._lock:
            self.events.insert(0, event)
            if len(self.events) > 1000:
                self.events = self.events[:1000]
        return True
    
    def get_events(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        events = self.events
        if scan_id:
            events = [e for e in events if e.get('scan_id') == scan_id]
        return events[:limit]
    
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        with self._lock:
            self.findings.insert(0, finding)
            severity = finding.get('severity', 'medium').lower()
            self.stats['total_findings'] += 1
            if severity in ('critical', 'high', 'medium', 'low'):
                self.stats[f'{severity}_count'] += 1
        return True
    
    def get_findings(self, scan_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        findings = self.findings
        if scan_id:
            findings = [f for f in findings if f.get('scan_id') == scan_id]
        return findings[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()
    
    def update_stats(self, stats: Dict[str, Any]) -> bool:
        with self._lock:
            self.stats.update(stats)
        return True
    
    def get_active_scans(self) -> Dict[str, Dict[str, Any]]:
        return {k: v for k, v in self.scans.items() if v.get('status') == 'running'}
    
    def mark_scan_complete(self, scan_id: str, status: str = 'complete'):
        if scan_id in self.scans:
            self.scans[scan_id]['status'] = status
            self.scans[scan_id]['completed_at'] = datetime.utcnow().isoformat()
            self.stats['total_scans'] += 1
    
    # =========================================================================
    # Report Release Workflow Implementation (In-Memory)
    # =========================================================================
    
    def create_report(self, report: Dict[str, Any]) -> str:
        """Create a new report in STAGED status."""
        report_id = report.get('report_id') or f"rpt_{uuid.uuid4().hex[:12]}"
        client_id = report.get('client_id')
        
        if not client_id:
            raise ValueError("client_id is required for report creation")
        
        hash_input = f"{client_id}:{report.get('scan_id')}:{datetime.utcnow().isoformat()}"
        report_hash = report.get('hash') or hashlib.sha256(hash_input.encode()).hexdigest()
        
        with self._lock:
            self.reports[report_id] = {
                'report_id': report_id,
                'client_id': client_id,
                'scan_id': report.get('scan_id', ''),
                'status': ReportStatus.STAGED.value,
                'version': report.get('version', 1),
                'title': report.get('title', f"Security Report - {client_id}"),
                'artifact_paths': report.get('artifact_paths', {}),
                'hash': report_hash,
                'findings_count': report.get('findings_count', 0),
                'notes': report.get('notes', ''),
                'created_at': datetime.utcnow().isoformat(),
                'approved_at': None,
                'released_at': None,
                'revoked_at': None,
                'approved_by': None,
                'released_by': None,
                'revoked_by': None,
            }
        
        self.log_report_action(
            report_id=report_id,
            action='created',
            actor=report.get('created_by', 'system'),
            details={'client_id': client_id, 'scan_id': report.get('scan_id')}
        )
        
        return report_id
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a report by ID."""
        return self.reports.get(report_id)
    
    def list_reports(
        self,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List reports, optionally filtered."""
        reports = list(self.reports.values())
        
        if client_id:
            reports = [r for r in reports if r.get('client_id') == client_id]
        if status:
            reports = [r for r in reports if r.get('status') == status]
        
        return sorted(reports, key=lambda x: x.get('created_at', ''), reverse=True)[:limit]
    
    def update_report_status(
        self,
        report_id: str,
        new_status: str,
        actor: str,
        ip_address: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """Update report status."""
        if report_id not in self.reports:
            return False
        
        try:
            status_enum = ReportStatus(new_status)
        except ValueError:
            raise ValueError(f"Invalid status: {new_status}")
        
        report = self.reports[report_id]
        current_status = report.get('status')
        
        valid_transitions = {
            ReportStatus.STAGED.value: [ReportStatus.APPROVED.value],
            ReportStatus.APPROVED.value: [ReportStatus.RELEASED.value, ReportStatus.STAGED.value],
            ReportStatus.RELEASED.value: [ReportStatus.REVOKED.value],
            ReportStatus.REVOKED.value: [ReportStatus.RELEASED.value],
        }
        
        if new_status not in valid_transitions.get(current_status, []):
            raise ValueError(f"Invalid transition from {current_status} to {new_status}")
        
        with self._lock:
            report['status'] = new_status
            if notes:
                report['notes'] = notes
            
            now = datetime.utcnow().isoformat()
            if new_status == ReportStatus.APPROVED.value:
                report['approved_at'] = now
                report['approved_by'] = actor
            elif new_status == ReportStatus.RELEASED.value:
                report['released_at'] = now
                report['released_by'] = actor
            elif new_status == ReportStatus.REVOKED.value:
                report['revoked_at'] = now
                report['revoked_by'] = actor
        
        action_map = {
            ReportStatus.APPROVED.value: 'approved',
            ReportStatus.RELEASED.value: 'released',
            ReportStatus.REVOKED.value: 'revoked',
            ReportStatus.STAGED.value: 'returned_to_staged',
        }
        
        self.log_report_action(
            report_id=report_id,
            action=action_map.get(new_status, 'status_changed'),
            actor=actor,
            ip_address=ip_address,
            details={'previous_status': current_status, 'new_status': new_status, 'notes': notes}
        )
        
        return True
    
    def get_report_audit_log(self, report_id: str) -> List[Dict[str, Any]]:
        """Get audit log entries for a report."""
        return [e for e in self.report_audit_log if e.get('report_id') == report_id]
    
    def log_report_action(
        self,
        report_id: str,
        action: str,
        actor: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Log an action on a report."""
        with self._lock:
            self.report_audit_log.insert(0, {
                'id': f"log_{uuid.uuid4().hex[:12]}",
                'report_id': report_id,
                'action': action,
                'actor': actor,
                'ip_address': ip_address,
                'details': details,
                'timestamp': datetime.utcnow().isoformat()
            })
        return True
    
    def get_report_release_confirmation(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get data needed for release confirmation."""
        report = self.get_report(report_id)
        if not report:
            return None
        
        client_slug = report['client_id'].replace(' ', '_').lower()
        version = report.get('version', 1)
        confirmation_string = f"RELEASE {client_slug} {version}"
        
        return {
            'report_id': report_id,
            'client_id': report['client_id'],
            'client_slug': client_slug,
            'version': version,
            'hash': report.get('hash'),
            'title': report.get('title'),
            'findings_count': report.get('findings_count', 0),
            'confirmation_string': confirmation_string
        }
    
    def verify_release_confirmation(self, report_id: str, confirmation: str) -> bool:
        """Verify the typed confirmation string matches."""
        expected = self.get_report_release_confirmation(report_id)
        if not expected:
            return False
        return confirmation.strip() == expected['confirmation_string']


# Global storage instance
_storage_instance: Optional[StorageBackend] = None


def get_storage() -> StorageBackend:
    """Get the global storage instance based on STORAGE_BACKEND env var."""
    global _storage_instance
    if _storage_instance is None:
        backend = os.getenv('STORAGE_BACKEND', 'memory').lower()
        
        if backend == 'sqlite':
            db_path = os.getenv('SQLITE_PATH', '/data/dashboard.db')
            _storage_instance = SQLiteStorage(db_path)
        else:
            _storage_instance = MemoryStorage()
        
        _storage_instance.initialize()
    
    return _storage_instance

