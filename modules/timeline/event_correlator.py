"""
Event Correlator for Timeline Mode
Correlates events from multiple sources to build attack timeline
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
from core.log_parser import LogEvent


class EventCorrelator:
    """Correlates events from multiple sources"""

    def __init__(self):
        self.events: List[LogEvent] = []

    def add_events(self, events: List[LogEvent]):
        """Add events from a source"""
        self.events.extend(events)

    def get_all_events(self) -> List[LogEvent]:
        """Get all events sorted by timestamp"""
        return sorted(self.events, key=lambda e: e.timestamp)

    def get_events_by_type(self, event_type: str) -> List[LogEvent]:
        """Get events filtered by type"""
        return [e for e in self.events if e.event_type == event_type]

    def get_events_in_window(self, start: datetime, end: datetime) -> List[LogEvent]:
        """Get events within a time window"""
        return [e for e in self.events
                if start <= e.timestamp <= end]

    def find_related_events(self, event: LogEvent, time_window_seconds: int = 300) -> List[LogEvent]:
        """Find events related to a given event within a time window"""
        start = event.timestamp - timedelta(seconds=time_window_seconds)
        end = event.timestamp + timedelta(seconds=time_window_seconds)

        related = self.get_events_in_window(start, end)
        return [e for e in related if e != event]

    def detect_attack_patterns(self) -> List[Dict[str, Any]]:
        """Detect common attack patterns from event sequences"""
        patterns = []

        # Pattern 1: Failed sudo followed by successful sudo
        sudo_failed = self.get_events_by_type('SUDO_FAILED')
        sudo_command = self.get_events_by_type('SUDO_COMMAND')

        for failed in sudo_failed:
            # Look for successful sudo within 10 minutes
            related = self.find_related_events(failed, time_window_seconds=600)
            successful = [e for e in related if e.event_type == 'SUDO_COMMAND']

            if successful:
                patterns.append({
                    'pattern': 'sudo_brute_force_success',
                    'severity': 'CRITICAL',
                    'description': 'Failed sudo attempts followed by successful sudo',
                    'events': [failed] + successful
                })

        # Pattern 2: Multiple SUID executions in short time
        suid_events = self.get_events_by_type('SUID_EXECUTION')
        if len(suid_events) > 5:
            # Group by time windows
            time_groups = self._group_by_time_window(suid_events, window_seconds=60)
            for group in time_groups:
                if len(group) > 3:
                    patterns.append({
                        'pattern': 'suid_enumeration',
                        'severity': 'HIGH',
                        'description': 'Multiple SUID binary executions detected',
                        'events': group
                    })

        # Pattern 3: Cron activity followed by suspicious commands
        cron_events = self.get_events_by_type('CRON_SUSPICIOUS')
        for cron_event in cron_events:
            related = self.find_related_events(cron_event, time_window_seconds=120)
            if related:
                patterns.append({
                    'pattern': 'cron_exploitation',
                    'severity': 'CRITICAL',
                    'description': 'Suspicious cron activity with related events',
                    'events': [cron_event] + related
                })

        return patterns

    def _group_by_time_window(self, events: List[LogEvent],
                              window_seconds: int = 60) -> List[List[LogEvent]]:
        """Group events into time windows"""
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        groups = []
        current_group = [sorted_events[0]]

        for event in sorted_events[1:]:
            if (event.timestamp - current_group[-1].timestamp).total_seconds() <= window_seconds:
                current_group.append(event)
            else:
                groups.append(current_group)
                current_group = [event]

        if current_group:
            groups.append(current_group)

        return groups

    def get_timeline_summary(self) -> Dict[str, Any]:
        """Get a summary of the timeline"""
        events_by_type = defaultdict(int)
        for event in self.events:
            events_by_type[event.event_type] += 1

        return {
            'total_events': len(self.events),
            'events_by_type': dict(events_by_type),
            'time_range': {
                'start': min(e.timestamp for e in self.events) if self.events else None,
                'end': max(e.timestamp for e in self.events) if self.events else None
            }
        }
