"""
Timeline Builder for PrivWatch
Constructs chronological attack timeline from correlated events
"""

from typing import List, Dict, Any
from datetime import datetime
from core.log_parser import LogEvent
from modules.timeline.event_correlator import EventCorrelator
from core.logger import Logger


class TimelineBuilder:
    """Builds and visualizes attack timeline"""

    def __init__(self):
        self.correlator = EventCorrelator()

    def add_events(self, events: List[LogEvent]):
        """Add events from a source"""
        self.correlator.add_events(events)

    def build_timeline(self) -> List[Dict[str, Any]]:
        """Build the attack timeline"""
        events = self.correlator.get_all_events()
        patterns = self.correlator.detect_attack_patterns()

        timeline = []

        # Add individual events
        for event in events:
            timeline.append({
                'timestamp': event.timestamp,
                'type': 'event',
                'event_type': event.event_type,
                'source': event.source,
                'details': event.details
            })

        # Add detected patterns
        for pattern in patterns:
            timeline.append({
                'timestamp': pattern['events'][0].timestamp if pattern['events'] else datetime.now(),
                'type': 'pattern',
                'pattern': pattern['pattern'],
                'severity': pattern['severity'],
                'description': pattern['description'],
                'event_count': len(pattern['events'])
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline

    def print_timeline(self):
        """Print timeline to console"""
        Logger.header("ATTACK TIMELINE")

        timeline = self.build_timeline()

        if not timeline:
            Logger.info("No events detected")
            return

        Logger.info(f"Total timeline entries: {len(timeline)}")
        print()

        for entry in timeline:
            timestamp = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

            if entry['type'] == 'event':
                Logger.info(f"[{timestamp}] {entry['event_type']}")
                print(f"    Source: {entry['source']}")
                if entry['details']:
                    for key, value in entry['details'].items():
                        print(f"    {key}: {value}")
                print()

            elif entry['type'] == 'pattern':
                severity = entry['severity']
                if severity == 'CRITICAL':
                    Logger.critical(f"[{timestamp}] PATTERN DETECTED: {entry['pattern']}")
                else:
                    Logger.warning(f"[{timestamp}] PATTERN DETECTED: {entry['pattern']}")

                print(f"    {entry['description']}")
                print(f"    Events involved: {entry['event_count']}")
                print()

        # Print summary
        summary = self.correlator.get_timeline_summary()
        Logger.header("TIMELINE SUMMARY")
        print(f"Total Events: {summary['total_events']}")
        print(f"\nEvents by Type:")
        for event_type, count in summary['events_by_type'].items():
            print(f"  {event_type}: {count}")

        if summary['time_range']['start']:
            print(f"\nTime Range:")
            print(f"  Start: {summary['time_range']['start'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  End: {summary['time_range']['end'].strftime('%Y-%m-%d %H:%M:%S')}")
