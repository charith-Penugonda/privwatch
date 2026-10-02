#!/usr/bin/env python3
"""
PrivWatch v2.0 - Privilege Escalation Detection & Forensics
Complete three-mode tool for Red Team, Blue Team, and Timeline analysis
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Core imports
from core.logger import Logger
from core.scanner import Finding

# Red Mode scanners
from modules.red_mode.suid_scanner import SuidScanner
from modules.red_mode.sudo_scanner import SudoScanner
from modules.red_mode.passwd_scanner import PasswdScanner
from modules.red_mode.cron_scanner import CronScanner
from modules.red_mode.kernel_scanner import KernelScanner
from modules.red_mode.capabilities_scanner import CapabilitiesScanner

# Blue Mode detectors
from modules.blue_mode.suid_detector import SuidDetector
from modules.blue_mode.sudo_detector import SudoDetector
from modules.blue_mode.passwd_detector import PasswdDetector
from modules.blue_mode.cron_detector import CronDetector
from modules.blue_mode.kernel_detector import KernelDetector
from modules.blue_mode.capabilities_detector import CapabilitiesDetector

# Timeline components
from modules.timeline.timeline_builder import TimelineBuilder

# Report generators
from reports.json_exporter import JSONExporter
from reports.pdf_generator import PDFGenerator

# Utils
from utils.system_info import is_root, get_os_info, get_kernel_version


class PrivWatch:
    """Main PrivWatch application"""

    VERSION = "2.0"

    def __init__(self, mode='red', output_dir=None, report_format='json'):
        self.mode = mode
        self.output_dir = output_dir or './reports'
        self.report_format = report_format
        self.findings = []
        self.timeline_builder = TimelineBuilder()

        # Create output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def run(self):
        """Execute PrivWatch based on selected mode"""
        Logger.banner(self.mode, self.VERSION)

        if not is_root() and self.mode == 'red':
            Logger.warning("Not running as root - some scans may be limited")
            print()

        start_time = datetime.now()

        if self.mode == 'red':
            self._run_red_mode()
        elif self.mode == 'blue':
            self._run_blue_mode()
        elif self.mode == 'timeline':
            self._run_timeline_mode()
        else:
            Logger.error(f"Invalid mode: {self.mode}")
            return

        # Generate report
        if self.findings:
            self._generate_report()

        elapsed = (datetime.now() - start_time).total_seconds()
        Logger.success(f"\nScan completed in {elapsed:.2f} seconds")
        print()

    def _run_red_mode(self):
        """Execute Red Team enumeration mode"""
        Logger.header("RED TEAM MODE - Privilege Escalation Enumeration")

        # System info
        os_info = get_os_info()
        kernel = get_kernel_version()
        Logger.info(f"Target: {os_info['system']} {kernel}")
        print()

        # Run all scanners
        scanners = [
            ("SUID/SGID Binaries", SuidScanner()),
            ("Sudo Configuration", SudoScanner()),
            ("Password Files", PasswdScanner()),
            ("Cron Jobs", CronScanner()),
            ("Kernel Exploits", KernelScanner()),
            ("Capabilities", CapabilitiesScanner())
        ]

        for name, scanner in scanners:
            Logger.header(f"Scanning: {name}")
            findings = scanner.scan()
            self.findings.extend(findings)

            # Print summary
            if findings:
                critical = len([f for f in findings if f.severity == 'CRITICAL'])
                high = len([f for f in findings if f.severity == 'HIGH'])
                Logger.warning(f"Found {len(findings)} findings ({critical} CRITICAL, {high} HIGH)")
            else:
                Logger.success("No findings")
            print()

        # Summary
        self._print_summary()

    def _run_blue_mode(self):
        """Execute Blue Team log analysis mode"""
        Logger.header("BLUE TEAM MODE - Log Forensics & Detection")

        Logger.info("Analyzing system logs for privilege escalation attempts...")
        print()

        # Run all detectors
        detectors = [
            ("Sudo Activity", SudoDetector()),
            ("SUID Execution", SuidDetector()),
            ("Password File Access", PasswdDetector()),
            ("Cron Activity", CronDetector()),
            ("Kernel Indicators", KernelDetector()),
            ("Capabilities Activity", CapabilitiesDetector())
        ]

        for name, detector in detectors:
            Logger.header(f"Analyzing: {name}")
            findings = detector.parse()
            self.findings.extend(findings)

            # Collect events for timeline
            events = detector.get_events()
            if events:
                self.timeline_builder.add_events(events)

            # Print summary
            if findings:
                critical = len([f for f in findings if f.severity == 'CRITICAL'])
                high = len([f for f in findings if f.severity == 'HIGH'])
                Logger.critical(f"Detected {len(findings)} findings ({critical} CRITICAL, {high} HIGH)")
            else:
                Logger.success("No suspicious activity detected")
            print()

        # Summary
        self._print_summary()

    def _run_timeline_mode(self):
        """Execute Timeline reconstruction mode"""
        Logger.header("TIMELINE MODE - Attack Reconstruction")

        Logger.info("Correlating events from multiple sources...")
        print()

        # Run Blue Mode detectors to collect events
        detectors = [
            SudoDetector(),
            SuidDetector(),
            PasswdDetector(),
            CronDetector(),
            KernelDetector(),
            CapabilitiesDetector()
        ]

        for detector in detectors:
            findings = detector.parse()
            self.findings.extend(findings)

            events = detector.get_events()
            if events:
                self.timeline_builder.add_events(events)

        # Build and display timeline
        self.timeline_builder.print_timeline()

        # Export timeline
        timeline = self.timeline_builder.build_timeline()
        events = self.timeline_builder.correlator.get_all_events()
        patterns = self.timeline_builder.correlator.detect_attack_patterns()

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        timeline_file = f"{self.output_dir}/timeline_{timestamp}.json"
        JSONExporter.export_timeline(events, patterns, timeline_file)
        Logger.success(f"\nTimeline exported: {timeline_file}")

    def _print_summary(self):
        """Print scan summary"""
        Logger.header("SCAN SUMMARY")

        if not self.findings:
            Logger.success("No findings detected")
            return

        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        vector_counts = {}

        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            vector_counts[finding.vector] = vector_counts.get(finding.vector, 0) + 1

        # Print severity breakdown
        print(f"{Logger.RED}CRITICAL: {severity_counts['CRITICAL']}{Logger.RESET}")
        print(f"{Logger.YELLOW}HIGH: {severity_counts['HIGH']}{Logger.RESET}")
        print(f"{Logger.BLUE}MEDIUM: {severity_counts['MEDIUM']}{Logger.RESET}")
        print(f"{Logger.GREEN}LOW: {severity_counts['LOW']}{Logger.RESET}")
        print(f"\nTotal Findings: {len(self.findings)}")

        # Print vector breakdown
        print(f"\n{Logger.BOLD}Findings by Vector:{Logger.RESET}")
        for vector, count in sorted(vector_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vector}: {count}")

        # Show top findings
        print(f"\n{Logger.BOLD}Top Critical/High Findings:{Logger.RESET}")
        critical_high = [f for f in self.findings if f.severity in ['CRITICAL', 'HIGH']]
        for i, finding in enumerate(critical_high[:5], 1):
            print(f"{i}. [{finding.severity}] {finding.title}")

        if len(critical_high) > 5:
            print(f"   ... and {len(critical_high) - 5} more")

    def _generate_report(self):
        """Generate output report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if self.report_format == 'json':
            output_file = f"{self.output_dir}/privwatch_{self.mode}_{timestamp}.json"
            JSONExporter.export_findings(self.findings, output_file, self.mode)
            Logger.success(f"\nReport generated: {output_file}")

        elif self.report_format == 'pdf':
            output_file = f"{self.output_dir}/privwatch_{self.mode}_{timestamp}.pdf"
            result = PDFGenerator.generate_report(self.findings, output_file, self.mode)
            Logger.success(f"\nReport generated: {result}")

        elif self.report_format == 'both':
            # JSON
            json_file = f"{self.output_dir}/privwatch_{self.mode}_{timestamp}.json"
            JSONExporter.export_findings(self.findings, json_file, self.mode)

            # PDF
            pdf_file = f"{self.output_dir}/privwatch_{self.mode}_{timestamp}.pdf"
            result = PDFGenerator.generate_report(self.findings, pdf_file, self.mode)

            Logger.success(f"\nReports generated:")
            Logger.success(f"  - {json_file}")
            Logger.success(f"  - {result}")


def main():
    parser = argparse.ArgumentParser(
        description='PrivWatch - Privilege Escalation Detection & Forensics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Red Team Mode:     python3 privwatch_v2.py --mode red
  Blue Team Mode:    python3 privwatch_v2.py --mode blue
  Timeline Mode:     python3 privwatch_v2.py --mode timeline

  With JSON report:  python3 privwatch_v2.py --mode red --format json
  With PDF report:   python3 privwatch_v2.py --mode blue --format pdf
  Both formats:      python3 privwatch_v2.py --mode red --format both

Modes:
  red      - Enumerate privilege escalation vectors (attacker perspective)
  blue     - Analyze logs for exploitation attempts (defender perspective)
  timeline - Reconstruct chronological attack timeline from logs
        """
    )

    parser.add_argument(
        '--mode',
        choices=['red', 'blue', 'timeline'],
        default='red',
        help='Operation mode (default: red)'
    )

    parser.add_argument(
        '--output',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )

    parser.add_argument(
        '--format',
        choices=['json', 'pdf', 'both'],
        default='json',
        help='Report format (default: json)'
    )

    args = parser.parse_args()

    # Check if running as root (recommended)
    if not is_root():
        print(f"{Logger.YELLOW}[!] Not running as root - some checks may be limited{Logger.RESET}\n")

    # Run PrivWatch
    privwatch = PrivWatch(
        mode=args.mode,
        output_dir=args.output,
        report_format=args.format
    )

    try:
        privwatch.run()
    except KeyboardInterrupt:
        print(f"\n\n{Logger.YELLOW}[!] Scan interrupted by user{Logger.RESET}")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Error during scan: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
