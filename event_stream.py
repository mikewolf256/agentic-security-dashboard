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


class ScanEventStream:
    """Minimal event stream publisher for scan visibility."""
    
    def __init__(self, max_events: int = 100):
        """Initialize the event stream."""
        self.max_events = max_events
        self._events: List[ScanEvent] = []
        self._listeners: List[Callable[[ScanEvent], None]] = []
        self._current_scan_id: Optional[str] = None
        self._scan_start_time: Optional[datetime] = None
        self._stats: Dict[str, int] = {
            "requests_sent": 0,
            "endpoints_found": 0,
            "payloads_tested": 0,
            "findings_discovered": 0,
        }
    
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
        elif event_type == EventType.PAYLOAD_SENT:
            self._stats["payloads_tested"] += 1
        elif event_type == EventType.FINDING_VALIDATED:
            self._stats["findings_discovered"] += 1
        elif event_type == EventType.SCAN_START:
            self._current_scan_id = scan_id
            self._scan_start_time = datetime.utcnow()
        
        # Notify listeners
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                print(f"Error in event listener: {e}")
        
        return event
    
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
        
        return {
            "stats": self._stats.copy(),
            "duration_seconds": duration_seconds,
            "scan_id": self._current_scan_id,
        }


# Global instance
_stream_instance: Optional[ScanEventStream] = None


def get_event_stream() -> ScanEventStream:
    """Get the global event stream instance."""
    global _stream_instance
    if _stream_instance is None:
        _stream_instance = ScanEventStream()
    return _stream_instance

