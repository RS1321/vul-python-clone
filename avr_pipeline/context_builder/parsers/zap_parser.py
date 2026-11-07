"""OWASP ZAP JSON parser for extracting DAST findings."""

import json
from typing import Any, Dict, List
from pathlib import Path

from .models import DASTFinding, DastRequest, DastResponse


class ZAPParser:
    """Parser for OWASP ZAP JSON report files."""

    def __init__(self):
        """Initialize ZAP parser."""
        pass

    def parse(self, zap_report_path: str) -> List[DASTFinding]:
        """
        Parse ZAP JSON report and extract all findings.

        Args:
            zap_report_path: Path to full-scan-report.json file

        Returns:
            List of DASTFinding objects
        """
        try:
            with open(zap_report_path, 'r', encoding='utf-8') as f:
                zap_data = json.load(f)
            
            findings = []

            # ZAP structure: site[].alerts[]
            sites = zap_data.get("site", [])
            if not sites:
                return findings

            for site in sites:
                alerts = site.get("alerts", [])

                for alert in alerts:
                    # Each alert can have multiple instances
                    instances = alert.get("instances", [])

                    if not instances:
                        # Create a single finding without instance details
                        finding = self._create_finding_without_instance(alert)
                        if finding:
                            findings.append(finding)
                    else:
                        # Create finding for each unique instance
                        for instance in instances:
                            finding = self.extract_finding(alert, instance)
                            if finding:
                                findings.append(finding)

            return findings

        except Exception as e:
            print(f"✗ Error parsing ZAP report: {e}")
            return []

    def extract_finding(
        self, alert: Dict[str, Any], instance: Dict[str, Any]
    ) -> DASTFinding:
        """
        Extract single DAST finding from alert and instance.

        Args:
            alert: ZAP alert object
            instance: Specific instance of the alert

        Returns:
            DASTFinding object
        """
        try:
            # Extract alert metadata
            alert_name = alert.get("alert", "Unknown Alert")
            alert_id = str(alert.get("alertRef", alert.get("pluginid", "0")))
            # ZAP JSON has no "risk" key — use "riskcode" (string int: 3/2/1/0)
            _riskcode_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
            risk = _riskcode_map.get(str(alert.get("riskcode", "1")), "low")
            confidence = alert.get("confidence", "Medium")
            description = alert.get("desc", "")

            # Extract CWE
            cwe = self.extract_cwe(alert)

            # Extract request details
            request = self.extract_request(instance, alert_name)

            # Extract response details
            response = self.extract_response(instance)

            return DASTFinding(
                present=True,
                tool="owasp-zap",
                alert_id=alert_id,
                risk=risk.lower(),
                confidence=confidence.lower(),
                cwe=cwe,
                request=request,
                response=response,
                description=description,
            )

        except Exception:
            # Return minimal finding on error
            return DASTFinding(
                present=True,
                tool="owasp-zap",
                description="Error parsing finding",
            )

    def _create_finding_without_instance(
        self, alert: Dict[str, Any]
    ) -> DASTFinding:
        """Create finding when no specific instances are available."""
        try:
            alert_name = alert.get("alert", "Unknown Alert")
            alert_id = str(alert.get("alertRef", alert.get("pluginid", "0")))
            _riskcode_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
            risk = _riskcode_map.get(str(alert.get("riskcode", "1")), "low")
            confidence = alert.get("confidence", "Medium")
            description = alert.get("desc", "")
            cwe = self.extract_cwe(alert)

            return DASTFinding(
                present=True,
                tool="owasp-zap",
                alert_id=alert_id,
                risk=risk.lower(),
                confidence=confidence.lower(),
                cwe=cwe,
                description=description,
            )

        except Exception:
            return None

    def extract_request(
        self, instance: Dict[str, Any], alert_name: str
    ) -> DastRequest:
        """
        Extract HTTP request details from instance.

        Args:
            instance: ZAP instance object
            alert_name: Name of the alert

        Returns:
            DastRequest object
        """
        method = instance.get("method", "GET")
        url = instance.get("uri", "")
        attack = instance.get("attack", "")
        param = instance.get("param", "")
        evidence = instance.get("evidence", attack or param or alert_name)

        return DastRequest(
            method=method,
            url=url,
            evidence=evidence,
        )

    def extract_response(self, instance: Dict[str, Any]) -> DastResponse:
        """
        Extract HTTP response and determine attack success.

        Args:
            instance: ZAP instance object

        Returns:
            DastResponse object
        """
        # Extract response details
        evidence = instance.get("evidence", "")
        other_info = instance.get("otherinfo", "")

        # ZAP doesn't provide status code directly in all cases
        # We'll infer from evidence or set a default
        status_code = 200  # Default assumption

        # Determine if attack was successful
        attack_successful = self._determine_attack_success(
            evidence, other_info, instance
        )

        return DastResponse(
            status_code=status_code,
            evidence=evidence or other_info,
            attack_successful=attack_successful,
        )

    def _determine_attack_success(
        self, evidence: str, other_info: str, instance: Dict[str, Any]
    ) -> bool:
        """
        Determine if the attack was successful based on heuristics.

        Args:
            evidence: Evidence from response
            other_info: Additional information
            instance: Full instance object

        Returns:
            True if attack appears successful, False otherwise
        """
        # Heuristics for successful attacks
        success_indicators = [
            "error",
            "exception",
            "syntax",
            "sql",
            "database",
            "warning",
            "injection",
            "stack trace",
            "vulnerable",
        ]

        combined_text = (evidence + " " + other_info).lower()

        # Check if any success indicator is present
        for indicator in success_indicators:
            if indicator in combined_text:
                return True

        # If attack payload is present in evidence, consider it successful
        attack = instance.get("attack", "")
        if attack and attack in evidence:
            return True

        return False

    def extract_cwe(self, alert: Dict[str, Any]) -> str:
        """
        Extract CWE ID from alert.

        Args:
            alert: ZAP alert object

        Returns:
            CWE identifier (e.g., "CWE-89") or None
        """
        try:
            cweid = alert.get("cweid")
            if cweid:
                cweid_str = str(cweid)
                # Skip sentinel values that carry no real CWE mapping
                if cweid_str in ("0", "-1", ""):
                    return None
                if not cweid_str.startswith("CWE-"):
                    return f"CWE-{cweid_str}"
                return cweid_str
            return None

        except Exception:
            return None

    def map_risk_level(self, zap_risk: str) -> str:
        """
        Map ZAP risk levels to standard scale.

        Args:
            zap_risk: ZAP risk level (High, Medium, Low, Informational)

        Returns:
            Standard severity level
        """
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }
        return mapping.get(zap_risk.lower(), "medium")
