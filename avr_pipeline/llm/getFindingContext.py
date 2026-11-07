"""
Finding Context Extractor

Extracts finding details from filtered_context.json
"""

import json
import sys
from pathlib import Path
from typing import Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'context_builder' / 'parsers'))
from code_fetcher import CodeFetcher


def load_filtered_context(context_path: str) -> Dict:
    """
    Load filtered_context.json
    
    Args:
        context_path: Path to filtered_context.json
    
    Returns:
        Context dict
    """
    with open(context_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_finding_details(finding: Dict, repo_path: str) -> Dict:
    """
    Extract detailed information from a finding
    
    Args:
        finding: Finding object from filtered_context.json
        repo_path: Path to repository
    
    Returns:
        Dict with extracted details
    """
    sast_info = finding.get('sast', {}) or {}
    dast_info = finding.get('dast', {}) or {}
    location = sast_info.get('location', {}) or {}
    
    # Get file path
    file_path = location.get('file_path', '')
    if not file_path:
        return None
    
    full_path = Path(repo_path) / file_path
    
    # Get function name and line numbers
    function_name = location.get('function')
    start_line = location.get('start_line', 0)
    
    # Initialize code fetcher
    code_fetcher = CodeFetcher(repo_path)
    
    # Get ONLY the vulnerable function, not the full file
    vulnerable_function_code = None
    if function_name:
        function_result = code_fetcher.get_function_by_name(file_path, function_name)
        if function_result:
            fn_start, fn_end, fn_code = function_result
            # Names are bound once against the immutable baseline. Scan lines
            # become stale after sequential fixes; do not use them to reject a name.
            vulnerable_function_code = fn_code
            start_line = fn_start
        else:
            # A missing/ambiguous bound name must never select a different function.
            return None
    
    # Fallback: If function not found, get function containing the vulnerable line
    if not vulnerable_function_code:
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to extract function containing the vulnerable line
            import ast
            tree = ast.parse(content)
            lines = content.split('\n')
            
            from parsers.ast_utils import function_at
            match = function_at(tree, start_line)
            if match:
                function_name, node = match
                vulnerable_function_code = '\n'.join(lines[node.lineno - 1:node.end_lineno])
            
            # If still not found, use a window around the vulnerable line
            if not vulnerable_function_code:
                context_lines = 20  # Show 20 lines before and after
                start_idx = max(0, start_line - context_lines - 1)
                end_idx = min(len(lines), start_line + context_lines)
                vulnerable_function_code = '\n'.join(lines[start_idx:end_idx])
        
        except Exception as e:
            print(f"⚠️  Error extracting function: {e}")
            return None
    
    # Extract vulnerable code snippet (already has context lines)
    code_snippet = sast_info.get('vulnerable_code', '')
    
    # Build analysis dict
    analysis = {
        'severity_score': 0,  # TODO: Calculate from severity
        'confidence': sast_info.get('confidence', 'unknown'),
        'risk_level': finding.get('baseline_severity', 'unknown'),
        'justification': sast_info.get('description', ''),
        'exploitability_assessment': 'See DAST evidence' if dast_info.get('present') else 'Static analysis only',
        'impact_assessment': f"CWE-{sast_info.get('cwe', 'unknown')} vulnerability detected"
    }
    
    # Calculate severity score (simple mapping)
    severity_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30}
    analysis['severity_score'] = severity_map.get(finding.get('baseline_severity', 'low'), 30)
    
    return {
        'finding': finding,
        'analysis': analysis,
        'vulnerable_function_code': vulnerable_function_code,
        'code_snippet': code_snippet,
        'file_path': file_path,
        'full_path': str(full_path),
        'start_line': start_line,
        'end_line': fn_end if function_name and vulnerable_function_code and 'fn_end' in locals() else (location.get('end_line') or start_line),
        'function_name': function_name
    }


def get_findings_metadata_only(context_path: str, max_findings: Optional[int] = None, finding_ids: Optional[list] = None) -> list:
    """
    Load findings metadata WITHOUT extracting code (for just-in-time processing)
    
    Args:
        context_path: Path to filtered_context.json
        max_findings: Maximum number of findings to return
        finding_ids: Optional list of specific finding IDs to process
    
    Returns:
        List of finding dicts (raw from filtered_context.json)
    """
    context = load_filtered_context(context_path)
    findings = context.get('findings', [])

    # Exclude DAST-only findings — the pipeline can only patch code when a SAST
    # location (file path + line number) is present.  DAST-only alerts have no
    # actionable code location and must be addressed through configuration /
    # infrastructure changes, not source-code patches.
    dast_only = [
        f.get('finding_id') for f in findings
        if not f.get('sast', {}).get('present', False)
    ]
    if dast_only:
        print(f"   ⚠️  Skipping {len(dast_only)} DAST-only finding(s) (no SAST location to patch):")
        for fid in dast_only:
            print(f"      - {fid}")
    findings = [f for f in findings if f.get('sast', {}).get('present', False)]

    # Filter by specific finding IDs if provided
    if finding_ids:
        findings = [f for f in findings if f.get('finding_id') in finding_ids]

    if max_findings:
        findings = findings[:max_findings]

    return findings


def refresh_finding_code(finding: Dict, repo_path: str) -> Dict:
    """
    Refresh finding with CURRENT code from working branch (just-in-time)
    
    This fetches the latest function code from the current branch state,
    preventing stale code issues when multiple findings target the same function.
    
    Args:
        finding: Finding object from filtered_context.json
        repo_path: Path to repository (working branch)
    
    Returns:
        Dict with updated finding details and current code
    """
    details = get_finding_details(finding, repo_path)
    
    if details:
        # Update the finding's vulnerable_code field with CURRENT function code
        # This ensures the LLM sees the latest state, including previous fixes
        sast_info = finding.get('sast', {})
        if sast_info and details.get('vulnerable_function_code'):
            # Format as code snippet with line markers (similar to original format)
            function_code = details['vulnerable_function_code']
            sast_info['vulnerable_code'] = f"[CURRENT CODE FROM BRANCH]\n{function_code}"
    
    return details


def get_all_findings(context_path: str, repo_path: str, max_findings: Optional[int] = None, finding_ids: Optional[list] = None) -> list:
    """
    Get all findings with details (LEGACY - extracts code at load time)
    
    ⚠️  WARNING: This pre-loads code and can become stale if multiple findings
    target the same function. Use get_findings_metadata_only() + refresh_finding_code()
    for just-in-time processing instead.
    
    Args:
        context_path: Path to filtered_context.json
        repo_path: Path to repository
        max_findings: Maximum number of findings to return
        finding_ids: Optional list of specific finding IDs to process
    
    Returns:
        List of finding detail dicts
    """
    context = load_filtered_context(context_path)
    findings = context.get('findings', [])
    
    # Filter by specific finding IDs if provided
    if finding_ids:
        findings = [f for f in findings if f.get('finding_id') in finding_ids]
    
    if max_findings:
        findings = findings[:max_findings]
    
    results = []
    for finding in findings:
        details = get_finding_details(finding, repo_path)
        if details:
            results.append(details)
    
    return results
