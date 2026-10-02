"""
Base Log Parser Class for Blue Mode
Abstract base class for all log analysis modules
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
import re
from core.scanner import Finding


class LogEvent:
    """Standardized log event structure"""

    def __init__(self, timestamp: datetime, event_type: str,
                 source: str, details: Dict[str, Any]):
        self.timestamp = timestamp
        self.event_type = event_type
        self.source = source
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'source': self.source,
            'details': self.details
        }


class LogParser(ABC):
    """Abstract base class for all log parser modules"""

    def __init__(self, vector_name: str):
        self.vector_name = vector_name
        self.findings: List[Finding] = []
        self.events: List[LogEvent] = []

    def parse_syslog_timestamp(self, line: str) -> Optional[datetime]:
        """Parse syslog timestamp from log line"""
        # Format: Oct  2 16:30:45
        try:
            parts = line.split()
            if len(parts) >= 3:
                month = parts[0]
                day = parts[1]
                time = parts[2]

                # Construct datetime (use current year)
                year = datetime.now().year
                timestamp_str = f"{year} {month} {day} {time}"
                return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except Exception:
            pass
        return None

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str, remediation: str = ""):
        """Add a new finding to the results"""
        finding = Finding(
            vector=self.vector_name,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation
        )
        self.findings.append(finding)

    def add_event(self, timestamp: datetime, event_type: str,
                  source: str, details: Dict[str, Any]):
        """Add a log event"""
        event = LogEvent(timestamp, event_type, source, details)
        self.events.append(event)

    @abstractmethod
    def parse(self, log_file: str) -> List[Finding]:
        """Parse log file and return findings"""
        pass

    def get_findings(self) -> List[Finding]:
        """Return all findings"""
        return self.findings

    def get_events(self) -> List[LogEvent]:
        """Return all events"""
        return self.events
