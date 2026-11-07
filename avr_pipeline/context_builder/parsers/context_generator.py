"""Context generator for combining SAST and DAST findings."""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from .models import Finding, SASTFinding, DASTFinding


class ContextGenerator:
    """Generate context.json from SAST and DAST findings."""

    def __init__(self):
        """Initialize context generator."""
        self.findings = []
        self.correlation_groups = {}

    def add_sast_findings(self, sast_findings: List[SASTFinding]):
        """
        Add SAST findings to context.

        Args:
            sast_findings: List of SAST findings from CodeQL
        """
        for sast in sast_findings:
            # Create a combined finding with SAST data
            finding_id = self._generate_finding_id(sast, None)
            
            # Create empty DAST finding
            dast = DASTFinding(present=False)
            
            # Determine baseline severity
            baseline_severity = self._determine_baseline_severity(sast, dast)
            
            finding = Finding(
                finding_id=finding_id,
                sast=sast,
                dast=dast,
                baseline_severity=baseline_severity,
                correlation_group=None
            )
            
            self.findings.append(finding)

    def add_dast_findings(self, dast_findings: List[DASTFinding]):
        """
        Add DAST findings to context.

        Args:
            dast_findings: List of DAST findings from OWASP ZAP
        """
        for dast in dast_findings:
            # Try to correlate with existing SAST findings (can match multiple)
            correlated_findings = []
            
            for existing_finding in self.findings:
                if self._can_correlate(existing_finding.sast, dast):
                    correlated_findings.append(existing_finding)
            
            if correlated_findings:
                # Get or create correlation group for this CWE
                correlation_group = None
                
                # Check if any already have a group
                for finding in correlated_findings:
                    if finding.correlation_group is not None:
                        correlation_group = finding.correlation_group
                        break
                
                # Create new group if needed
                if correlation_group is None:
                    correlation_group = self._get_next_correlation_group()
                
                # Apply correlation group to all matching SAST findings
                for finding in correlated_findings:
                    # Only update DAST if not already set (keep first DAST instance)
                    if not finding.dast.present:
                        finding.dast = dast
                        finding.baseline_severity = self._determine_baseline_severity(
                            finding.sast, dast
                        )
                    finding.correlation_group = correlation_group
            else:
                # Create new finding with only DAST data
                finding_id = self._generate_finding_id(None, dast)
                
                # Create empty SAST finding
                sast = SASTFinding(present=False)
                
                baseline_severity = self._determine_baseline_severity(sast, dast)
                
                finding = Finding(
                    finding_id=finding_id,
                    sast=sast,
                    dast=dast,
                    baseline_severity=baseline_severity,
                    correlation_group=None
                )
                
                self.findings.append(finding)

    def _can_correlate(self, sast: SASTFinding, dast: DASTFinding) -> bool:
        """
        Determine if SAST and DAST findings can be correlated.

        Args:
            sast: SAST finding
            dast: DAST finding

        Returns:
            True if findings should be correlated
        """
        # Correlation based on CWE (normalized)
        if sast.present and dast.present:
            if sast.cwe and dast.cwe:
                # Normalize CWE format (CWE-089 and CWE-89 should match)
                sast_cwe_num = sast.cwe.replace("CWE-", "").lstrip("0") or "0"
                dast_cwe_num = dast.cwe.replace("CWE-", "").lstrip("0") or "0"
                return sast_cwe_num == dast_cwe_num
        
        return False

    def _get_next_correlation_group(self) -> int:
        """Get next correlation group number."""
        existing_groups = [
            f.correlation_group for f in self.findings 
            if f.correlation_group is not None
        ]
        return max(existing_groups, default=0) + 1

    def _generate_finding_id(self, sast: SASTFinding, dast: DASTFinding) -> str:
        """Generate unique finding ID."""
        if sast and sast.present:
            return f"sast-{sast.rule_id}-{sast.location.file_path if sast.location else 'unknown'}:{sast.location.start_line if sast.location else 0}"
        elif dast and dast.present:
            return f"dast-{dast.alert_id}-{dast.request.url if dast.request else 'unknown'}"
        else:
            return f"finding-{len(self.findings)}"

    def _determine_baseline_severity(
        self, sast: SASTFinding, dast: DASTFinding
    ) -> str:
        """
        Determine baseline severity from SAST and DAST findings.

        Args:
            sast: SAST finding
            dast: DAST finding

        Returns:
            Severity level (critical, high, medium, low)
        """
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        severities = []
        
        if sast.present and sast.severity:
            severities.append(sast.severity)
        
        if dast.present and dast.risk:
            # Map DAST risk to SAST severity scale
            risk_mapping = {
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "info"
            }
            mapped_risk = risk_mapping.get(dast.risk.lower(), "medium")
            severities.append(mapped_risk)
        
        if not severities:
            return "medium"
        
        # Return highest severity
        return max(severities, key=lambda s: severity_order.get(s, 0))

    def generate_context(self, output_path: str, config: Dict[str, Any]):
        """
        Generate context.json file.

        Args:
            output_path: Path to save context.json
            config: Configuration dictionary
        """
        # Calculate summary statistics
        total_findings = len(self.findings)
        sast_findings = sum(1 for f in self.findings if f.sast.present)
        dast_findings = sum(1 for f in self.findings if f.dast.present)
        correlated_findings = sum(1 for f in self.findings if f.correlation_group is not None)
        
        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            severity = finding.baseline_severity
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Build context structure
        context = {
            "scan_summary": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": total_findings,
                "sast_findings": sast_findings,
                "dast_findings": dast_findings,
                "correlated_findings": correlated_findings,
                **severity_counts
            },
            "configuration": config,
            "findings": [f.to_dict() for f in self.findings]
        }
        
        # Save to file
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(context, f, indent=2)
        
        print(f"✓ Generated context.json with {total_findings} findings")
        print(f"  - SAST: {sast_findings}")
        print(f"  - DAST: {dast_findings}")
        print(f"  - Correlated: {correlated_findings}")
        
        # Show correlation breakdown by CWE
        if correlated_findings > 0:
            cwe_groups = {}
            for finding in self.findings:
                if finding.correlation_group is not None:
                    cwe = finding.sast.cwe if finding.sast.present else finding.dast.cwe
                    if cwe:
                        cwe_groups[cwe] = cwe_groups.get(cwe, 0) + 1
            print(f"  - Correlation groups:")
            for cwe, count in sorted(cwe_groups.items()):
                print(f"    • {cwe}: {count} findings")
