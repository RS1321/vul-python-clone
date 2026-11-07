"""CodeQL SARIF parser for extracting SAST findings."""

import json
import ast
from typing import Dict, List, Optional, Any
from pathlib import Path

from .models import (
    SASTFinding,
    CodeLocation,
    DataFlow,
    DataFlowStep,
)
from .code_fetcher import CodeFetcher


def get_function_at_line(file_path: str, line_number: int) -> Optional[str]:
    """
    Get the function name that contains a specific line number using AST.
    
    Args:
        file_path: Path to Python file
        line_number: Line number to check
    
    Returns:
        Function name or None if module-level code
    """
    try:
        # Validate path exists
        if not Path(file_path).exists():
            return None
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        # Walk AST to find function containing the line
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_start = node.lineno
                func_end = node.end_lineno if node.end_lineno else func_start
                
                # Check if line is within this function
                if func_start <= line_number <= func_end:
                    return node.name
        
        return None  # Module-level code
    except (SyntaxError, UnicodeDecodeError, FileNotFoundError):
        # File has syntax errors or encoding issues - skip AST detection
        return None
    except Exception:
        # Any other error - skip AST detection
        return None


class CodeQLParser:
    """Parser for CodeQL SARIF output files."""

    def __init__(self, code_fetcher: CodeFetcher, config: Dict):
        """
        Initialize CodeQL parser.

        Args:
            code_fetcher: Code fetcher for retrieving code context
            config: Configuration dictionary for code context extraction
        """
        self.code_fetcher = code_fetcher
        self.config = config
        self.rule_index = {}  # Maps rule_id -> rule metadata (including CWE tags)

    def parse(self, sarif_file_path: str) -> List[SASTFinding]:
        """
        Parse SARIF file and extract all findings.

        Args:
            sarif_file_path: Path to python-results.sarif file

        Returns:
            List of SASTFinding objects
        """
        try:
            with open(sarif_file_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            findings = []

            # Build rule index FIRST (CWE codes are in rule definitions)
            self._build_rule_index(sarif_data)

            # SARIF structure: runs[0].results[]
            runs = sarif_data.get("runs", [])
            if not runs:
                return findings

            run = runs[0]
            results = run.get("results", [])

            for idx, result in enumerate(results):
                try:
                    finding = self.extract_finding(result)
                    if finding:
                        findings.append(finding)
                    else:
                        # Debug: track why finding was None
                        pass
                except Exception as e:
                    # Debug: print errors instead of silently continuing
                    print(f"  ⚠️  Skipped result {idx}: {str(e)[:100]}")
                    continue

            return findings

        except Exception as e:
            print(f"✗ Error parsing SARIF file: {e}")
            return []

    def _build_rule_index(self, sarif_data: Dict[str, Any]) -> None:
        """
        Build an index of rule_id -> rule metadata (including CWE tags).

        CodeQL stores CWE codes in rule definitions, not in individual results.
        Searches through:
        - runs[].tool.driver.rules[]
        - runs[].tool.extensions[].rules[] (CodeQL typically uses this)

        Args:
            sarif_data: Full SARIF JSON data
        """
        self.rule_index = {}

        for run in sarif_data.get("runs", []):
            tool = run.get("tool", {})

            # Check driver rules
            driver = tool.get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id")
                if rule_id:
                    self.rule_index[rule_id] = rule

            # Check extension rules (CodeQL stores rules here!)
            for extension in tool.get("extensions", []):
                for rule in extension.get("rules", []):
                    rule_id = rule.get("id")
                    if rule_id:
                        self.rule_index[rule_id] = rule

    def extract_finding(self, result: Dict[str, Any]) -> Optional[SASTFinding]:
        """
        Extract single finding from SARIF result.

        Args:
            result: SARIF result object

        Returns:
            SASTFinding object or None if extraction fails
        """
        try:
            # Extract basic info
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            # Severity lives on the rule definition, NOT on the result object.
            # CodeQL never sets result.level, so always look it up via rule_index.
            rule_meta = self.rule_index.get(rule_id, {})
            level = rule_meta.get("defaultConfiguration", {}).get("level", "warning")

            # Extract location
            locations = result.get("locations", [])
            if not locations:
                return None

            location = self.extract_location(locations[0])
            if not location:
                return None

            # Extract CWE
            cwe = self.extract_cwe(result)

            # Map severity
            severity = self.map_severity(level)

            # Extract confidence (if available)
            confidence = result.get("properties", {}).get("precision", "medium")

            # Extract data flow
            data_flow = self.extract_data_flow(result)

            # Fetch code context
            vulnerable_code = None
            try:
                vulnerable_code = self.code_fetcher.get_code_context(
                    location.file_path, location.start_line, self.config
                )
            except Exception:
                pass

            return SASTFinding(
                present=True,
                tool="codeql",
                rule_id=rule_id,
                severity=severity,
                confidence=confidence,
                cwe=cwe,
                location=location,
                vulnerable_code=vulnerable_code,
                data_flow=data_flow,
                description=message,
            )

        except Exception as e:
            # Debug: print errors instead of silently returning None
            print(f"  ⚠️  Failed to extract finding: {str(e)[:100]}")
            return None

    def extract_location(self, location_obj: Dict[str, Any]) -> Optional[CodeLocation]:
        """
        Extract code location from SARIF location object.

        Args:
            location_obj: SARIF location object

        Returns:
            CodeLocation object or None
        """
        try:
            physical_location = location_obj.get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})

            file_path = artifact_location.get("uri", "")
            start_line = region.get("startLine", 1)
            end_line = region.get("endLine", start_line)

            # Extract function name if available — ONLY from SARIF logicalLocations.
            # Do NOT fall back to AST-on-current-file: the working file may have been
            # modified by previous pipeline runs, so get_function_at_line() would return
            # whichever function currently occupies that line, not the original one.
            # A stale function name causes JIT re-fetch to silently return the wrong
            # function body to the LLM (e.g. insecure_deserialization instead of
            # command_injection). Leaving function=None forces the line-number-based
            # AST fallback inside get_finding_details(), which is safer.
            logical_locations = location_obj.get("logicalLocations", [])
            function = None
            if logical_locations:
                function = logical_locations[0].get("name")

            return CodeLocation(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                function=function,
            )

        except Exception as e:
            print(f"  ⚠️  Failed to extract location: {str(e)[:100]}")
            return None

    def extract_data_flow(self, result: Dict[str, Any]) -> Optional[DataFlow]:
        """
        Extract taint tracking / data flow information.

        Args:
            result: SARIF result object

        Returns:
            DataFlow object or None
        """
        try:
            code_flows = result.get("codeFlows", [])
            if not code_flows:
                return None

            # Get first code flow
            thread_flows = code_flows[0].get("threadFlows", [])
            if not thread_flows:
                return None

            locations = thread_flows[0].get("locations", [])
            if not locations:
                return None

            steps = []
            for idx, flow_location in enumerate(locations, start=1):
                location = flow_location.get("location", {})
                physical_location = location.get("physicalLocation", {})
                artifact = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})

                file_path = artifact.get("uri", "unknown")
                line = region.get("startLine", 0)
                message = location.get("message", {}).get("text", "")

                step = DataFlowStep(
                    step=idx,
                    location=f"{file_path}:{line}",
                    node=message,
                )
                steps.append(step)

            return DataFlow(full_path=steps) if steps else None

        except Exception:
            return None

    def map_severity(self, sarif_level: str) -> str:
        """
        Map SARIF severity levels to standard scale.

        Args:
            sarif_level: SARIF level (error, warning, note, none)

        Returns:
            Standard severity (critical, high, medium, low)
        """
        mapping = {
            "error": "high",
            "warning": "medium",
            "note": "low",
            "none": "info",
        }
        return mapping.get(sarif_level.lower(), "medium")

    def extract_cwe(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE from rule definition via rule_id lookup.

        CodeQL stores CWE codes in rule definitions (tool.extensions[].rules[]),
        not in individual result objects.

        Args:
            result: SARIF result object

        Returns:
            CWE identifier (e.g., "CWE-89", "CWE-327") or None
        """
        try:
            rule_id = result.get("ruleId")
            if not rule_id or rule_id not in self.rule_index:
                return None

            rule = self.rule_index[rule_id]
            properties = rule.get("properties", {})
            tags = properties.get("tags", [])

            # Find CWE tags (format: "external/cwe/cwe-089")
            cwe_codes = []
            for tag in tags:
                if "cwe" in tag.lower() and "/" in tag:
                    # Extract CWE number from "external/cwe/cwe-089"
                    parts = tag.split("/")
                    cwe_part = parts[-1]  # "cwe-089"
                    if cwe_part.lower().startswith("cwe-"):
                        cwe_number = cwe_part.split("-")[-1]  # "089"
                        cwe_codes.append(f"CWE-{cwe_number.upper()}")

            if not cwe_codes:
                return None

            # Return primary CWE (first one)
            # Note: Some rules have multiple CWEs (e.g., weak-hashing: CWE-327, CWE-328, CWE-916)
            return cwe_codes[0]

        except Exception:
            return None
