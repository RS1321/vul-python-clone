"""Data models for security findings."""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


@dataclass
class CodeLocation:
    """Location of vulnerable code."""
    file_path: str
    start_line: int
    end_line: int = None
    function: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DataFlowStep:
    """Single step in a data flow path."""
    step: int
    location: str
    node: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DataFlow:
    """Data flow / taint tracking information."""
    full_path: List[DataFlowStep]

    def to_dict(self) -> Dict:
        return {"full_path": [step.to_dict() for step in self.full_path]}


@dataclass
class SASTFinding:
    """SAST finding from CodeQL."""
    present: bool = False
    tool: str = "codeql"
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    cwe: Optional[str] = None
    location: Optional[CodeLocation] = None
    vulnerable_code: Optional[str] = None
    data_flow: Optional[DataFlow] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict:
        result = {
            "present": self.present,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "description": self.description,
        }
        
        if self.location:
            result["location"] = self.location.to_dict()
        
        if self.vulnerable_code:
            result["vulnerable_code"] = self.vulnerable_code
        
        if self.data_flow:
            result["data_flow"] = self.data_flow.to_dict()
        
        return result


@dataclass
class DastRequest:
    """HTTP request details."""
    method: str
    url: str
    evidence: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DastResponse:
    """HTTP response details."""
    status_code: int
    evidence: str
    attack_successful: bool

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DASTFinding:
    """DAST finding from OWASP ZAP."""
    present: bool = False
    tool: str = "owasp-zap"
    alert_id: Optional[str] = None
    risk: Optional[str] = None
    confidence: Optional[str] = None
    cwe: Optional[str] = None
    request: Optional[DastRequest] = None
    response: Optional[DastResponse] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict:
        result = {
            "present": self.present,
            "tool": self.tool,
            "alert_id": self.alert_id,
            "risk": self.risk,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "description": self.description,
        }
        
        if self.request:
            result["request"] = self.request.to_dict()
        
        if self.response:
            result["response"] = self.response.to_dict()
        
        return result


@dataclass
class Finding:
    """Combined SAST + DAST finding."""
    finding_id: str
    sast: SASTFinding
    dast: DASTFinding
    baseline_severity: str
    correlation_group: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "sast": self.sast.to_dict(),
            "dast": self.dast.to_dict(),
            "baseline_severity": self.baseline_severity,
            "correlation_group": self.correlation_group,
        }
