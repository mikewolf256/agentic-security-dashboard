#!/usr/bin/env python3
"""Standalone Event Stream for Dashboard

Minimal event stream implementation for the dashboard.
Can be replaced with import from main project if available.
"""

import json
import time
from enum import Enum
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from dataclasses import dataclass, asdict


class EventType(Enum):
    """Scan event types for the live dashboard."""
    # Scan lifecycle
    SCAN_START = "scan_start"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    
    # Scan phases
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    PROGRESS_UPDATE = "progress_update"
    
    # Discovery events
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    TECH_FINGERPRINT = "tech_fingerprint"
    JS_FILE_FOUND = "js_file_found"
    API_ENDPOINT = "api_endpoint"
    
    # Testing events
    PAYLOAD_SENT = "payload_sent"
    REQUEST_MADE = "request_made"
    RESPONSE_RECEIVED = "response_received"
    
    # Finding events
    FINDING_CANDIDATE = "finding_candidate"
    FINDING_VALIDATED = "finding_validated"
    FINDING_REJECTED = "finding_rejected"
    
    # RAG context
    RAG_MATCH = "rag_match"
    SIMILAR_VULN = "similar_vuln"
    
    # Validation
    HUMAN_VALIDATION_REQUIRED = "human_validation_required"
    POC_CONFIRMED = "poc_confirmed"


@dataclass
class ScanEvent:
    """A single scan event for streaming."""
    event_id: str
    event_type: str
    timestamp: str
    scan_id: str
    data: Dict[str, Any]
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScanPhase:
    """Scan phase enumeration."""
    RECON = "recon"
    SCANNING = "scanning"
    VALIDATION = "validation"
    COMPLETE = "complete"


class ScanEventStream:
    """Minimal event stream publisher for scan visibility."""
    
    def __init__(self, max_events: int = 100):
        """Initialize the event stream."""
        self.max_events = max_events
        self._events: List[ScanEvent] = []
        self._listeners: List[Callable[[ScanEvent], None]] = []
        self._current_scan_id: Optional[str] = None
        self._scan_start_time: Optional[datetime] = None
        self._current_phase: Optional[str] = None
        self._phase_start_time: Optional[datetime] = None
        self._progress_percentage: float = 0.0
        self._total_checks: int = 0
        self._completed_checks: int = 0
        self._tech_stack: Dict[str, Any] = {}
        self._owasp_coverage: Dict[str, Dict[str, Any]] = {}  # A01-A10 -> {tested: bool, count: int}
        self._endpoints: List[Dict[str, Any]] = []  # Recent endpoints
        self._endpoint_map: Dict[str, Dict[str, Any]] = {}  # URL -> endpoint details with findings
        self._stats: Dict[str, int] = {
            "requests_sent": 0,
            "endpoints_found": 0,
            "payloads_tested": 0,
            "findings_discovered": 0,
            "findings_validated": 0,
            "findings_candidates": 0,
        }
    
    def start_phase(self, phase: str, total_checks: Optional[int] = None):
        """Start a new scan phase."""
        if self._current_phase:
            # Complete previous phase
            self.complete_phase(self._current_phase)
        
        self._current_phase = phase
        self._phase_start_time = datetime.utcnow()
        if total_checks is not None:
            self._total_checks = total_checks
        
        self.emit(EventType.PHASE_START, {
            "phase": phase,
            "total_checks": total_checks,
            "start_time": self._phase_start_time.isoformat()
        })
    
    def complete_phase(self, phase: Optional[str] = None):
        """Complete the current or specified phase."""
        phase = phase or self._current_phase
        if not phase:
            return
        
        duration = None
        if self._phase_start_time:
            duration = (datetime.utcnow() - self._phase_start_time).total_seconds()
        
        self.emit(EventType.PHASE_COMPLETE, {
            "phase": phase,
            "duration_seconds": duration
        })
        
        if phase == self._current_phase:
            self._current_phase = None
            self._phase_start_time = None
    
    def update_progress(self, completed: int, total: Optional[int] = None, percentage: Optional[float] = None):
        """Update scan progress."""
        if total is not None:
            self._total_checks = total
        if completed is not None:
            self._completed_checks = completed
        
        if percentage is not None:
            self._progress_percentage = percentage
        elif self._total_checks > 0:
            self._progress_percentage = (self._completed_checks / self._total_checks) * 100.0
        
        # Calculate ETA
        eta_seconds = None
        if self._scan_start_time and self._progress_percentage > 0:
            elapsed = (datetime.utcnow() - self._scan_start_time).total_seconds()
            if self._progress_percentage < 100:
                eta_seconds = (elapsed / self._progress_percentage) * (100 - self._progress_percentage)
        
        self.emit(EventType.PROGRESS_UPDATE, {
            "percentage": self._progress_percentage,
            "completed": self._completed_checks,
            "total": self._total_checks,
            "eta_seconds": eta_seconds
        })
    
    def add_tech_fingerprint(self, tech: str, version: Optional[str] = None, confidence: Optional[str] = None):
        """Add a technology fingerprint to internal state (doesn't emit event)."""
        self._tech_stack[tech] = {
            "version": version,
            "confidence": confidence,
            "detected_at": datetime.utcnow().isoformat()
        }
        # Note: Don't call emit() here - it causes infinite recursion
        # The tech stack is updated in emit() when TECH_FINGERPRINT events arrive
    
    def update_owasp_coverage(self, category: str, tested: bool = True, count: int = 0):
        """Update OWASP Top 10 coverage for a category (A01-A10)."""
        if category not in self._owasp_coverage:
            self._owasp_coverage[category] = {"tested": False, "count": 0}
        
        self._owasp_coverage[category]["tested"] = tested
        self._owasp_coverage[category]["count"] += count
    
    def add_endpoint(self, endpoint: str, method: Optional[str] = None, status_code: Optional[int] = None):
        """Add a discovered endpoint."""
        now = datetime.utcnow().isoformat()
        endpoint_data = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "discovered_at": now
        }
        self._endpoints.insert(0, endpoint_data)
        if len(self._endpoints) > 100:  # Keep last 100
            self._endpoints.pop()
        
        # Also track in endpoint_map for detailed view
        endpoint_key = self._normalize_endpoint(endpoint)
        if endpoint_key not in self._endpoint_map:
            self._endpoint_map[endpoint_key] = {
                "url": endpoint,
                "method": method or "GET",
                "status_code": status_code,
                "discovered_at": now,
                "status": "discovered",  # discovered -> tested -> clean/vulnerable
                "findings": [],
                "payloads_tested": 0,
                "last_tested_at": None,
            }
    
    def _normalize_endpoint(self, url: str) -> str:
        """Normalize endpoint URL for consistent keying."""
        # Remove trailing slashes, normalize to lowercase domain
        url = url.rstrip("/")
        # Keep path case-sensitive but normalize protocol/domain
        if "://" in url:
            parts = url.split("://", 1)
            if "/" in parts[1]:
                domain, path = parts[1].split("/", 1)
                return f"{parts[0]}://{domain.lower()}/{path}"
            return f"{parts[0]}://{parts[1].lower()}"
        return url.lower()
    
    def add_finding_to_endpoint(self, endpoint: str, finding: Dict[str, Any]):
        """Associate a finding with an endpoint."""
        endpoint_key = self._normalize_endpoint(endpoint)
        if endpoint_key in self._endpoint_map:
            self._endpoint_map[endpoint_key]["findings"].append(finding)
            self._endpoint_map[endpoint_key]["status"] = "vulnerable"
            self._endpoint_map[endpoint_key]["last_tested_at"] = datetime.utcnow().isoformat()
    
    def mark_endpoint_tested(self, endpoint: str):
        """Mark an endpoint as tested (payloads sent)."""
        endpoint_key = self._normalize_endpoint(endpoint)
        if endpoint_key in self._endpoint_map:
            ep = self._endpoint_map[endpoint_key]
            ep["payloads_tested"] += 1
            ep["last_tested_at"] = datetime.utcnow().isoformat()
            if ep["status"] == "discovered":
                ep["status"] = "tested"
    
    def get_endpoint_details(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for a specific endpoint."""
        endpoint_key = self._normalize_endpoint(endpoint)
        return self._endpoint_map.get(endpoint_key)
    
    def get_all_endpoints(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all tracked endpoints with their status."""
        endpoints = list(self._endpoint_map.values())
        # Sort by: vulnerable first, then by discovery time
        endpoints.sort(key=lambda e: (
            0 if e["status"] == "vulnerable" else 1,
            e.get("discovered_at", "")
        ), reverse=True)
        return endpoints[:limit]
    
    def emit(self, event_type: EventType, data: Dict[str, Any], scan_id: Optional[str] = None) -> ScanEvent:
        """Emit a new event."""
        if scan_id is None:
            scan_id = self._current_scan_id or "default"
        
        event = ScanEvent(
            event_id=f"evt_{int(time.time() * 1000)}",
            event_type=event_type.value,
            timestamp=datetime.utcnow().isoformat(),
            scan_id=scan_id,
            data=data
        )
        
        # Add to events list
        self._events.insert(0, event)
        if len(self._events) > self.max_events:
            self._events.pop()
        
        # Update stats
        if event_type == EventType.REQUEST_MADE:
            self._stats["requests_sent"] += 1
        elif event_type == EventType.ENDPOINT_DISCOVERED:
            self._stats["endpoints_found"] += 1
            # Extract endpoint info if available
            endpoint = data.get("endpoint") or data.get("url")
            if endpoint:
                self.add_endpoint(endpoint, data.get("method"), data.get("status_code"))
        elif event_type == EventType.PAYLOAD_SENT:
            self._stats["payloads_tested"] += 1
            # Track which endpoint was tested
            endpoint = data.get("endpoint") or data.get("url") or data.get("target")
            if endpoint:
                self.mark_endpoint_tested(endpoint)
        elif event_type == EventType.FINDING_VALIDATED:
            self._stats["findings_discovered"] += 1
            self._stats["findings_validated"] += 1
            # Update OWASP coverage based on finding
            cwe = data.get("cwe") or data.get("cwe_id")
            if cwe:
                owasp_category = self._map_cwe_to_owasp(cwe)
                if owasp_category:
                    self.update_owasp_coverage(owasp_category, tested=True, count=1)
            # Associate finding with endpoint
            endpoint = data.get("endpoint") or data.get("url")
            if endpoint:
                finding_data = {
                    "title": data.get("title", "Unknown"),
                    "severity": data.get("severity", "medium"),
                    "status": "validated",
                    "cwe": cwe,
                    "timestamp": datetime.utcnow().isoformat(),
                    **{k: v for k, v in data.items() if k not in ("endpoint", "url")}
                }
                self.add_finding_to_endpoint(endpoint, finding_data)
        elif event_type == EventType.FINDING_CANDIDATE:
            self._stats["findings_candidates"] += 1
            # Associate candidate finding with endpoint
            endpoint = data.get("endpoint") or data.get("url")
            if endpoint:
                finding_data = {
                    "title": data.get("title", "Unknown"),
                    "severity": data.get("severity", "medium"),
                    "status": "candidate",
                    "cwe": data.get("cwe") or data.get("cwe_id"),
                    "timestamp": datetime.utcnow().isoformat(),
                    **{k: v for k, v in data.items() if k not in ("endpoint", "url")}
                }
                self.add_finding_to_endpoint(endpoint, finding_data)
        elif event_type == EventType.SCAN_START:
            self._current_scan_id = scan_id or data.get("scan_id", "default")
            self._scan_start_time = datetime.utcnow()
            self._progress_percentage = 0.0
            self._completed_checks = 0
            self._tech_stack = {}
            self._owasp_coverage = {}
            self._endpoints = []
            self._endpoint_map = {}  # Reset endpoint tracking
        elif event_type == EventType.TECH_FINGERPRINT:
            # Update tech stack directly (don't call add_tech_fingerprint to avoid recursion)
            tech = data.get("technology") or data.get("tech")
            if tech:
                self._tech_stack[tech] = {
                    "version": data.get("version"),
                    "confidence": data.get("confidence"),
                    "detected_at": datetime.utcnow().isoformat()
                }
        elif event_type == EventType.SCAN_PROGRESS or event_type == EventType.PROGRESS_UPDATE:
            # Update progress from scan_progress events
            if "progress" in data:
                self._progress_percentage = float(data["progress"])
            elif "progress_percentage" in data:
                self._progress_percentage = float(data["progress_percentage"])
            elif "percentage" in data:
                self._progress_percentage = float(data["percentage"])
            # Update completed/total if provided
            if "completed" in data:
                self._completed_checks = int(data["completed"])
            if "total" in data:
                self._total_checks = int(data["total"])
        elif event_type == EventType.PHASE_START:
            # Update current phase
            phase = data.get("phase")
            if phase:
                self._current_phase = phase
                self._phase_start_time = datetime.utcnow()
            # Also update progress if phase includes progress info
            if "progress_percentage" in data:
                self._progress_percentage = float(data["progress_percentage"])
        elif event_type == EventType.PHASE_COMPLETE:
            # Clear phase or mark complete
            if data.get("phase") == self._current_phase:
                self._phase_start_time = None
        elif event_type == EventType.SCAN_COMPLETE:
            # Mark scan as complete
            self._progress_percentage = 100.0
            self._current_phase = "complete"
        
        # Notify listeners
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                print(f"Error in event listener: {e}")
        
        return event
    
    def _map_cwe_to_owasp(self, cwe: str) -> Optional[str]:
        """Map CWE to OWASP Top 10 2025 category."""
        cwe_num = str(cwe).upper().replace("CWE-", "")
        # Simplified mapping - can be expanded
        mappings = {
            # A01 - Broken Access Control
            "639": "A01", "284": "A01", "285": "A01", "306": "A01",
            # A02 - Security Misconfiguration
            "16": "A02", "209": "A02", "215": "A02",
            # A03 - Software Supply Chain
            "1104": "A03",
            # A04 - Cryptographic Failures
            "327": "A04", "326": "A04", "295": "A04", "310": "A04",
            # A05 - Injection
            "79": "A05", "89": "A05", "78": "A05", "91": "A05", "918": "A05",
            # A06 - Insecure Design
            "703": "A06", "754": "A06",
            # A07 - Authentication Failures
            "287": "A07", "306": "A07", "798": "A07",
            # A08 - Data Integrity Failures
            "502": "A08", "915": "A08",
            # A09 - Logging & Monitoring Failures
            "778": "A09", "223": "A09",
            # A10 - Exception Handling
            "400": "A10", "703": "A10",
        }
        return mappings.get(cwe_num)
    
    def on_event(self, callback: Callable[[ScanEvent], None]):
        """Register a callback for new events."""
        self._listeners.append(callback)
    
    def get_recent_events(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get recent events as dictionaries."""
        return [event.to_dict() for event in self._events[:count]]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        duration_seconds = None
        if self._scan_start_time:
            duration_seconds = int((datetime.utcnow() - self._scan_start_time).total_seconds())
        
        # Calculate ETA
        eta_seconds = None
        if self._scan_start_time and self._progress_percentage > 0 and self._progress_percentage < 100:
            elapsed = (datetime.utcnow() - self._scan_start_time).total_seconds()
            eta_seconds = int((elapsed / self._progress_percentage) * (100 - self._progress_percentage))
        
        return {
            "stats": self._stats.copy(),
            "duration_seconds": duration_seconds,
            "scan_id": self._current_scan_id,
            "current_phase": self._current_phase,
            "progress_percentage": self._progress_percentage,
            "completed_checks": self._completed_checks,
            "total_checks": self._total_checks,
            "eta_seconds": eta_seconds,
            "tech_stack": self._tech_stack.copy(),
            "owasp_coverage": self._owasp_coverage.copy(),
            "recent_endpoints": self._endpoints[:10],  # Last 10 endpoints
            "endpoints_with_status": self.get_all_endpoints(20),  # Top 20 endpoints with status
        }


# Global instance
_stream_instance: Optional[ScanEventStream] = None


def get_event_stream() -> ScanEventStream:
    """Get the global event stream instance."""
    global _stream_instance
    if _stream_instance is None:
        _stream_instance = ScanEventStream()
    return _stream_instance

