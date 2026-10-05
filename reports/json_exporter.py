"""
JSON Report Exporter for PrivWatch
Exports findings and timeline to JSON format
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from core.scanner import Finding
from core.log_parser import LogEvent


class JSONExporter:
    """Export findings to JSON format"""

    @staticmethod
    def export_findings(findings: List[Finding], output_file: str, mode: str):
        """Export findings to JSON file"""
        report = {
            'metadata': {
                'tool': 'PrivWatch',
                'version': '1.0',
                'mode': mode,
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(findings)
            },
            'summary': JSONExporter._generate_summary(findings),
            'findings': [f.to_dict() for f in findings]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        return output_file

    @staticmethod
    def export_timeline(events: List[LogEvent], patterns: List[Dict[str, Any]],
                       output_file: str):
        """Export timeline to JSON file"""
        report = {
            'metadata': {
                'tool': 'PrivWatch',
                'version': '1.0',
                'mode': 'timeline',
                'timestamp': datetime.now().isoformat(),
                'total_events': len(events),
                'total_patterns': len(patterns)
            },
            'events': [e.to_dict() for e in events],
            'patterns': patterns
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        return output_file

    @staticmethod
    def _generate_summary(findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary statistics"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        vector_counts = {}

        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            vector_counts[finding.vector] = vector_counts.get(finding.vector, 0) + 1

        return {
            'by_severity': severity_counts,
            'by_vector': vector_counts
        }
