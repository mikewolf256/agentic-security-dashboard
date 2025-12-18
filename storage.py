#!/usr/bin/env python3
"""Persistence Layer for Agentic Security Dashboard

Provides storage backends for scan state, events, and findings.
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
"""

import os
import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import contextmanager


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


class MemoryStorage(StorageBackend):
    """In-memory storage for development/testing."""
    
    def __init__(self):
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
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

