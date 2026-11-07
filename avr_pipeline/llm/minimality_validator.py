"""
Minimality Validator

Validates that LLM fixes make minimal changes and provides specific retry feedback.
"""

import difflib
from typing import Dict, Tuple


def validate_fix_minimality(
    original_code: str,
    fixed_code: str,
    max_churn_ratio: float = 0.5,
    small_function_threshold: int = 15,
    small_function_max_lines: int = 5,
    absolute_max_churn: int = 50
) -> Tuple[bool, str, Dict]:
    """
    Validate fix doesn't make excessive changes relative to function size.
    
    Args:
        original_code: Original function code
        fixed_code: Fixed function code
        max_churn_ratio: Maximum allowed churn as ratio of original length (default: 50%)
        small_function_threshold: Functions under this length use absolute threshold (default: 15)
        small_function_max_lines: Maximum added plus deleted lines for small functions (default: 5)
        absolute_max_churn: Absolute safety net for pathological cases (default: 50)
    
    Returns:
        (is_valid, message, metrics_dict)
    """
    # Clean and count non-empty lines
    original_lines = [l for l in original_code.split('\n') if l.strip()]
    fixed_lines = [l for l in fixed_code.split('\n') if l.strip()]
    
    # Calculate diff
    diff = list(difflib.unified_diff(original_lines, fixed_lines, lineterm=''))
    
    lines_added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    lines_removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    total_churn = lines_added + lines_removed
    
    original_length = len(original_lines)
    churn_ratio = total_churn / original_length if original_length > 0 else 0
    
    metrics = {
        'original_length': original_length,
        'lines_added': lines_added,
        'lines_removed': lines_removed,
        'total_churn': total_churn,
        'churn_ratio': churn_ratio,
        'threshold_ratio': max_churn_ratio,
        'is_small_function': original_length < small_function_threshold
    }
    metrics['small_function_max_lines'] = small_function_max_lines
    
    # Edge case: Very small functions use absolute threshold
    if original_length < small_function_threshold:
        if total_churn > small_function_max_lines:
            return False, f"Excessive changes in small function: {total_churn} lines changed (max {small_function_max_lines} for functions <{small_function_threshold} lines)", metrics
        else:
            return True, f"Minimal changes in small function: {total_churn} lines changed", metrics
    
    # Pathological case safety net: Never allow >50 lines changed regardless of size
    if total_churn > absolute_max_churn:
        return False, f"Excessive changes: {total_churn} lines changed (absolute max: {absolute_max_churn} lines)", metrics
    
    # Relative threshold: churn can't exceed 50% of original function size
    if churn_ratio > max_churn_ratio:
        return False, f"Excessive changes: {total_churn} lines changed ({churn_ratio:.1%} of {original_length}-line function, max: {max_churn_ratio:.0%})", metrics
    
    return True, f"Minimal changes: {total_churn} lines changed ({churn_ratio:.0%} of function)", metrics


def generate_minimality_retry_instruction(
    validation_metrics: Dict,
    finding_details: Dict
) -> str:
    """
    Generate specific instruction for retry based on what went wrong.
    
    Args:
        validation_metrics: Metrics from validate_fix_minimality
        finding_details: Finding details with vulnerability info
    
    Returns:
        Specific retry instruction string
    """
    churn = validation_metrics['total_churn']
    original_length = validation_metrics['original_length']
    churn_ratio = validation_metrics['churn_ratio']
    threshold = validation_metrics['threshold_ratio']
    is_small = validation_metrics['is_small_function']
    
    vulnerable_line = finding_details.get('start_line', 'unknown')
    cwe = finding_details.get('cwe', 'unknown')
    file_path = finding_details.get('file_path', 'unknown')
    
    if is_small:
        max_lines = validation_metrics.get('small_function_max_lines', 5)
        threshold_desc = f"{max_lines} lines (small function threshold)"
    else:
        max_lines = int(original_length * threshold)
        threshold_desc = f"{threshold:.0%} of function length (≈{max_lines} lines)"
    
    return f"""
⚠️ RETRY REQUIRED: Your previous fix was too aggressive.

PROBLEM:
- You changed {churn} lines ({churn_ratio:.0%} of the {original_length}-line function)
- Maximum allowed: {threshold_desc}
- File: {file_path}, Line: {vulnerable_line}

SPECIFIC INSTRUCTIONS:
1. The vulnerability is {cwe} at line {vulnerable_line}
2. Focus ONLY on fixing that specific line - typically 1-5 lines changed
3. Do NOT rewrite the entire function
4. Preserve ALL surrounding code, error handling, return statements, and logic
5. Only modify what's absolutely necessary to eliminate the vulnerability

EXAMPLES OF MINIMAL FIXES:
- CWE-078 Command Injection: Change 2-3 lines (sanitize input, use shell=False)
- CWE-089 SQL Injection: Change 1-2 lines (parameterize query)
- CWE-079 XSS: Change 1 line (add html.escape())
- CWE-215 Debug Mode: Change 1 line (debug=True → debug=False)

TARGET: Change fewer than {max_lines} lines total
"""


def calculate_churn_reduction_ratio(initial_churn: int, final_churn: int) -> float:
    """
    Calculate how much the retry reduced churn (for academic metrics).
    
    Args:
        initial_churn: Churn before retry
        final_churn: Churn after retry
    
    Returns:
        Reduction ratio (e.g., 12.6 means 12.6x reduction)
    """
    if final_churn == 0:
        return float('inf') if initial_churn > 0 else 1.0
    return initial_churn / final_churn
