"""
Base Scanner Class for PrivWatch
Abstract base class for all enumeration modules
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any
import subprocess


class Finding:
    """Standardized finding structure across all modules"""

    def __init__(self, vector: str, severity: str, title: str,
                 description: str, evidence: str, remediation: str = ""):
        self.vector = vector
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'vector': self.vector,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'timestamp': self.timestamp.isoformat()
        }


class BaseScanner(ABC):
    """Abstract base class for all scanner modules"""

    def __init__(self, vector_name: str):
        self.vector_name = vector_name
        self.findings: List[Finding] = []

    def run_command(self, cmd: str, timeout: int = 30) -> str:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout}s"
        except Exception as e:
            return f"Error: {str(e)}"

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

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Execute the scan and return findings"""
        pass

    def get_findings(self) -> List[Finding]:
        """Return all findings"""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Return findings filtered by severity"""
        return [f for f in self.findings if f.severity == severity]
