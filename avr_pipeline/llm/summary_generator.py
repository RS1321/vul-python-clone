"""
Summary Generator

Generates human-readable summaries of fix attempts using LLM
"""
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime


class SummaryGenerator:
    """Generates summaries of vulnerability fixes"""
    
    def __init__(self, llm_client, branch_name: str):
        """
        Initialize summary generator
        
        Args:
            llm_client: LLM client instance
            branch_name: Current branch name
        """
        self.llm_client = llm_client
        self.branch_name = branch_name
        self.summaries: List[Dict[str, Any]] = []
    
    def generate_finding_summary(self, finding_number: str, finding_id: str, 
                                vulnerability_name: str, attempts_log: List[Dict[str, Any]],
                                final_outcome: Dict[str, Any]) -> str:
        """
        Generate a summary for a single finding using LLM
        
        Args:
            finding_number: Finding number (e.g., "FINDING 001")
            finding_id: Finding ID (e.g., "py/command-line-injection")
            vulnerability_name: Vulnerability name with CWE
            attempts_log: List of attempt details (what was tried, results)
            final_outcome: Final success/failure info
        
        Returns:
            Summary text
        """
        prompt = f"""You are analyzing an automated vulnerability fixing process. Generate a concise summary of what happened.

**Vulnerability Details:**
- Finding: {finding_number}
- Type: {vulnerability_name}
- ID: {finding_id}

**Fix Attempts:**
{self._format_attempts(attempts_log)}

**Final Outcome:**
- Success: {final_outcome.get('success', False)}
- Reason: {final_outcome.get('reason', 'N/A')}

**Task:** Write a 3-4 sentence summary explaining:
1. What the vulnerability was
2. What approach was taken to fix it
3. What worked or didn't work
4. The final result

Be concise and technical but clear. Focus on key insights."""

        try:
            response = self.llm_client.get_fix(
                prompt=prompt,
                system_prompt="You are a security engineer writing fix summaries. Be concise and factual.",
                purpose="summary_generation",
                metrics=None
            )
            return response.strip()
        except Exception as e:
            return f"Summary generation failed: {str(e)}"
    
    def _format_attempts(self, attempts_log: List[Dict[str, Any]]) -> str:
        """Format attempts log for prompt"""
        if not attempts_log:
            return "No attempts recorded"
        
        formatted = []
        for i, attempt in enumerate(attempts_log, 1):
            formatted.append(f"Attempt {i}:")
            formatted.append(f"  - Scope: {attempt.get('scope', 'unknown')}")
            formatted.append(f"  - Method: {attempt.get('method', 'unknown')}")
            
            validation = attempt.get('validation', {})
            if validation.get('pylint'):
                formatted.append(f"  - Pylint: {validation['pylint']}")
            if validation.get('pytest'):
                formatted.append(f"  - Pytest: {validation['pytest']}")
            
            if attempt.get('error'):
                formatted.append(f"  - Error: {attempt['error']}")
        
        return "\n".join(formatted)
    
    def add_finding_summary(self, finding_number: str, finding_id: str,
                          vulnerability_name: str, severity: str, cwe: str,
                          attempts_log: List[Dict[str, Any]], 
                          final_outcome: Dict[str, Any],
                          code_changes: Dict[str, Any],
                          commit_info: Dict[str, Any]):
        """
        Add a summary for a finding
        
        Args:
            finding_number: Finding number
            finding_id: Finding ID
            vulnerability_name: Vulnerability name
            severity: Severity level
            cwe: CWE identifier
            attempts_log: List of fix attempts
            final_outcome: Final result
            code_changes: Code change statistics
            commit_info: Git commit information
        """
        # Generate LLM summary
        llm_summary = self.generate_finding_summary(
            finding_number, finding_id, vulnerability_name,
            attempts_log, final_outcome
        )
        
        summary = {
            'finding_number': finding_number,
            'finding_id': finding_id,
            'vulnerability_name': vulnerability_name,
            'severity': severity,
            'cwe': cwe,
            'attempts_count': len(attempts_log),
            'attempts_log': attempts_log,
            'final_outcome': final_outcome,
            'code_changes': code_changes,
            'commit_info': commit_info,
            'llm_summary': llm_summary,
            'timestamp': datetime.now().isoformat()
        }
        
        self.summaries.append(summary)
    
    def update_finding_sast_validation(self, finding_id: str, sast_result: Dict[str, Any]):
        """Update a finding's summary with SAST validation result (Pattern 5 fix)
        
        Args:
            finding_id: The finding ID to update
            sast_result: SAST validation result dict with 'validated' and 'reason'
        """
        for summary in self.summaries:
            if summary['finding_id'] == finding_id:
                # Add SAST validation to the summary
                if 'sast_validation' not in summary:
                    summary['sast_validation'] = {}
                summary['sast_validation'] = {
                    'validated': sast_result.get('validated'),
                    'reason': sast_result.get('reason'),
                    'status': sast_result.get('status', 'unknown')
                }
                break
    
    def save_summaries(self) -> Path:
        """
        Save all summaries to summaries.json
        
        Returns:
            Path to summaries file
        """
        reports_dir = Path(__file__).parent.parent / 'reports' / self.branch_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        summaries_file = reports_dir / 'summaries.json'
        
        output = {
            'branch': self.branch_name,
            'generated_at': datetime.now().isoformat(),
            'total_findings': len(self.summaries),
            'findings': self.summaries
        }
        
        with open(summaries_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        return summaries_file
    
    def generate_pr_description(self, sast_validation_results: Dict[str, Any]) -> str:
        """
        Generate PR description with detailed report
        
        Args:
            sast_validation_results: SAST validation results dict
        
        Returns:
            Markdown-formatted PR description
        """
        successful_fixes = [s for s in self.summaries if s['final_outcome'].get('success', False)]
        failed_fixes = [s for s in self.summaries if not s['final_outcome'].get('success', False)]
        
        # Calculate SAST validation statistics
        validated_count = sum(1 for r in sast_validation_results.values() if r.get('validated'))
        still_detected_count = sum(1 for r in sast_validation_results.values() if not r.get('validated') and r.get('status') == 'still_present')
        
        # Build PR description
        lines = [
            "# 🔒 Automated Security Vulnerability Fixes",
            "",
            "## 📊 Summary",
            "",
            f"**Findings Addressed:** {len(self.summaries)}",
            f"**Successfully Applied:** {len(successful_fixes)}",
            f"**Failed to Apply:** {len(failed_fixes)}",
            "",
            "### 🔬 SAST Verification Results",
            f"- ✅ **{validated_count} vulnerabilities confirmed fixed** (no longer appear in SAST)",
            f"- ⚠️ **{still_detected_count} fixes applied but still detected** (may be false positives)",
            f"- 📈 **Verification Rate:** {validated_count}/{len(sast_validation_results)} ({(validated_count/len(sast_validation_results)*100) if sast_validation_results else 0:.1f}%)",
            "",
            f"**Branch:** `{self.branch_name}`",
            "",
            "---",
            ""
        ]
        
        # Add summary for each finding
        for summary in self.summaries:
            finding_num = summary['finding_number']
            vuln_name = summary['vulnerability_name']
            severity = summary['severity'].upper()
            success = summary['final_outcome'].get('success', False)
            
            icon = "✅" if success else "❌"
            lines.append(f"## {icon} {finding_num}: {vuln_name}")
            lines.append("")
            lines.append(f"**Severity:** {severity} | **CWE:** {summary['cwe']}")
            lines.append("")
            
            # Add LLM-generated summary
            lines.append("### Summary")
            lines.append(summary['llm_summary'])
            lines.append("")
            
            # Add code changes
            if success and summary['code_changes']:
                changes = summary['code_changes']
                lines.append("### Code Changes")
                lines.append(f"- **Files Modified:** {', '.join(changes.get('files_modified', []))}")
                lines.append(f"- **Lines Added:** {changes.get('lines_added', 0)}")
                lines.append(f"- **Lines Removed:** {changes.get('lines_removed', 0)}")
                
                if summary['commit_info'].get('commit_sha'):
                    lines.append(f"- **Commit:** `{summary['commit_info']['commit_sha'][:7]}`")
                lines.append("")
            
            # Add SAST validation result
            finding_id_full = summary['finding_id']
            sast_result = None
            for finding_key, result in sast_validation_results.items():
                if finding_id_full in finding_key or summary['finding_id'].replace('py/', 'sast-py/') in finding_key:
                    sast_result = result
                    break
            
            if sast_result:
                lines.append("### SAST Validation")
                if sast_result.get('validated'):
                    lines.append("✅ **Vulnerability confirmed fixed** - No longer detected in security scan")
                else:
                    lines.append(f"⚠️ {sast_result.get('reason', 'Unknown status')}")
                lines.append("")
            
            # Add fix attempts detail
            if summary['attempts_count'] > 1:
                lines.append(f"### Fix Attempts")
                lines.append(f"Required {summary['attempts_count']} attempts to achieve a working fix.")
                lines.append("")
            
            lines.append("---")
            lines.append("")
        
        # Add validation summary
        lines.append("## 🔬 Detailed Security Scan Validation")
        lines.append("")
        lines.append(f"**Total Vulnerabilities Verified:** {validated_count}/{len(sast_validation_results)}")
        lines.append("")
        
        if validated_count > 0:
            lines.append("### ✅ Confirmed Fixed (No Longer in SAST)")
            for finding_key, result in sast_validation_results.items():
                if result.get('validated'):
                    lines.append(f"- {finding_key}")
            lines.append("")
        
        if still_detected_count > 0:
            lines.append("### ⚠️ Still Detected by SAST")
            lines.append("*These fixes were applied correctly but SAST still detects them (possible false positives or semantic analysis limitations):*")
            lines.append("")
            for finding_key, result in sast_validation_results.items():
                if not result.get('validated') and result.get('status') == 'still_present':
                    lines.append(f"- {finding_key}: {result.get('reason', 'Unknown')}")
            lines.append("")
        
        lines.append("")
        
        # Add footer
        lines.append("---")
        lines.append("*This PR was automatically generated by the security remediation pipeline.*")
        
        return "\n".join(lines)
