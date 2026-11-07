"""
Metrics tracking for vulnerability fixing pipeline
"""
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class Metrics:
    """Track metrics for a single finding"""
    
    def __init__(self, finding_number: str, finding_id: str, vulnerability_name: str, 
                 severity: str = "unknown", cwe: str = "Unknown"):
        self.finding_number = finding_number
        self.finding_id = finding_id
        self.vulnerability_name = vulnerability_name
        
        # Security info
        self.severity = severity
        self.cwe = cwe
        
        # Timestamps
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.duration_seconds: Optional[float] = None
        
        # API calls
        self.api_calls: List[Dict[str, Any]] = []
        self.total_api_calls = 0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        
        # Iterations
        self.fix_attempts = 0
        self.validation_runs = {
            'pylint': 0,
            'pytest': 0,
            'sast': 0
        }
        
        # Validation results
        self.validation_results: List[Dict[str, Any]] = []
        self.final_pylint_score: Optional[float] = None
        self.final_pytest_result: Optional[bool] = None
        self.final_coverage_percent: Optional[float] = None
        self.sast_verified: Optional[bool] = None
        
        # Fix details
        self.fix_method: Optional[str] = None  # 'function', 'module', 'file'
        self.fix_scope: Optional[str] = None
        self.file_path: Optional[str] = None
        self.lines_changed: Optional[str] = None
        
        # Code change statistics
        self.lines_added: int = 0
        self.lines_removed: int = 0
        self.files_modified: List[str] = []
        self.commit_sha: Optional[str] = None
        self.commit_message: Optional[str] = None
        
        # Success
        self.fix_success = False
        self.failure_reason: Optional[str] = None
    
    def start_fix_attempt(self):
        """Record start of a fix attempt"""
        self.fix_attempts += 1
    
    def record_api_call(self, call_type: str, model: str, prompt_tokens: int, 
                       completion_tokens: int, total_tokens: int, 
                       duration_ms: float, purpose: str):
        """Record an API call"""
        self.api_calls.append({
            'call_number': len(self.api_calls) + 1,
            'call_type': call_type,
            'model': model,
            'purpose': purpose,
            'prompt_tokens': prompt_tokens,
            'completion_tokens': completion_tokens,
            'total_tokens': total_tokens,
            'duration_ms': duration_ms,
            'timestamp': datetime.now().isoformat()
        })
        self.total_api_calls += 1
        self.total_tokens += total_tokens
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
    
    def record_validation(self, validation_type: str, success: bool, 
                         score: Optional[float] = None, details: Optional[str] = None):
        """Record a validation run"""
        self.validation_runs[validation_type] = self.validation_runs.get(validation_type, 0) + 1
        
        result = {
            'validation_type': validation_type,
            'run_number': self.validation_runs[validation_type],
            'success': success,
            'timestamp': datetime.now().isoformat()
        }
        
        if score is not None:
            result['score'] = score
        if details:
            result['details'] = details
        
        self.validation_results.append(result)
        
        # Update final scores
        if validation_type == 'pylint' and score is not None:
            self.final_pylint_score = score
        elif validation_type == 'pytest':
            self.final_pytest_result = success
            if score is not None:
                self.final_coverage_percent = score  # score stores coverage %
        elif validation_type == 'sast':
            self.sast_verified = success
    
    def record_fix_details(self, fix_method: str, fix_scope: str, 
                          file_path: str, lines_changed: str,
                          lines_added: int = 0, lines_removed: int = 0,
                          files_modified: Optional[List[str]] = None):
        """Record details about the applied fix"""
        self.fix_method = fix_method
        self.fix_scope = fix_scope
        self.file_path = file_path
        self.lines_changed = lines_changed
        self.lines_added = lines_added
        self.lines_removed = lines_removed
        self.files_modified = files_modified or [file_path] if file_path else []
    
    def record_commit_info(self, commit_sha: str, commit_message: str):
        """Record Git commit information"""
        self.commit_sha = commit_sha
        self.commit_message = commit_message
    
    def mark_success(self):
        """Mark the fix as successful"""
        self.fix_success = True
        self.end_time = time.time()
        self.duration_seconds = round(self.end_time - self.start_time, 2)
    
    def mark_failure(self, reason: str):
        """Mark the fix as failed"""
        self.fix_success = False
        self.failure_reason = reason
        self.end_time = time.time()
        self.duration_seconds = round(self.end_time - self.start_time, 2)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            'finding_info': {
                'finding_number': self.finding_number,
                'finding_id': self.finding_id,
                'vulnerability_name': self.vulnerability_name,
                'severity': self.severity,
                'cwe': self.cwe
            },
            'timing': {
                'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
                'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
                'duration_seconds': self.duration_seconds
            },
            'api_usage': {
                'total_calls': self.total_api_calls,
                'total_tokens': self.total_tokens,
                'prompt_tokens': self.total_prompt_tokens,
                'completion_tokens': self.total_completion_tokens,
                'calls': self.api_calls
            },
            'iterations': {
                'fix_attempts': self.fix_attempts,
                'validation_runs': self.validation_runs,
                'total_validations': sum(self.validation_runs.values())
            },
            'validation_results': {
                'final_pylint_score': self.final_pylint_score,
                'final_pytest_result': self.final_pytest_result,
                'final_coverage_percent': self.final_coverage_percent,
                'sast_verified': self.sast_verified,
                'all_validations': self.validation_results
            },
            'fix_details': {
                'fix_method': self.fix_method,
                'fix_scope': self.fix_scope,
                'file_path': self.file_path,
                'lines_changed': self.lines_changed,
                'commit_sha': self.commit_sha,
                'commit_message': self.commit_message
            },
            'code_changes': {
                'lines_added': self.lines_added,
                'lines_removed': self.lines_removed,
                'files_modified': self.files_modified
            },
            'outcome': {
                'fix_success': self.fix_success,
                'failure_reason': self.failure_reason
            }
        }
    
    def save_to_file(self, branch_name: str):
        """Save metrics to reports/{branch}/metrics.json"""
        reports_dir = Path(__file__).parent.parent / 'reports' / branch_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        metrics_file = reports_dir / 'metrics.json'
        
        # Load existing metrics if file exists
        if metrics_file.exists():
            with open(metrics_file, 'r', encoding='utf-8') as f:
                all_metrics = json.load(f)
        else:
            all_metrics = {
                'branch': branch_name,
                'findings': [],
                'summary': {}
            }
        
        # Add or update this finding's metrics
        finding_metrics = self.to_dict()
        
        # Check if this finding already exists
        existing_idx = None
        for idx, m in enumerate(all_metrics['findings']):
            if m['finding_info']['finding_number'] == self.finding_number:
                existing_idx = idx
                break
        
        if existing_idx is not None:
            all_metrics['findings'][existing_idx] = finding_metrics
        else:
            all_metrics['findings'].append(finding_metrics)
        
        # Update summary
        total_findings = len(all_metrics['findings'])
        successful_fixes = sum(1 for m in all_metrics['findings'] if m['outcome']['fix_success'])
        failed_fixes = total_findings - successful_fixes
        
        # Count SAST-verified fixes (true success measure)
        sast_verified_fixes = sum(
            1 for m in all_metrics['findings'] 
            if m.get('validation_results', {}).get('sast_verified') is True
        )
        
        total_api_calls = sum(m['api_usage']['total_calls'] for m in all_metrics['findings'])
        total_tokens = sum(m['api_usage']['total_tokens'] for m in all_metrics['findings'])
        total_duration = sum(m['timing']['duration_seconds'] or 0 for m in all_metrics['findings'])
        
        all_metrics['summary'] = {
            'total_findings': total_findings,
            'successful_fixes': successful_fixes,
            'failed_fixes': failed_fixes,
            'success_rate': round(successful_fixes / total_findings * 100, 2) if total_findings > 0 else 0,
            'sast_verified_fixes': sast_verified_fixes,
            'sast_verified_rate': round(sast_verified_fixes / total_findings * 100, 2) if total_findings > 0 else 0,
            'total_api_calls': total_api_calls,
            'total_tokens': total_tokens,
            'total_duration_seconds': round(total_duration, 2),
            'average_duration_per_finding': round(total_duration / total_findings, 2) if total_findings > 0 else 0,
            'average_tokens_per_finding': round(total_tokens / total_findings, 2) if total_findings > 0 else 0
        }
        
        # Save to file
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(all_metrics, f, indent=2)
        
        return metrics_file


class MetricsCollector:
    """Central collector for all metrics during a pipeline run"""
    
    def __init__(self, branch_name: str):
        self.branch_name = branch_name
        self.current_metrics: Optional[Metrics] = None
    
    def start_finding(self, finding_number: str, finding_id: str, vulnerability_name: str,
                     severity: str = "unknown", cwe: str = "Unknown") -> Metrics:
        """Start tracking a new finding"""
        self.current_metrics = Metrics(finding_number, finding_id, vulnerability_name, severity, cwe)
        return self.current_metrics
    
    def get_current(self) -> Optional[Metrics]:
        """Get current metrics object"""
        return self.current_metrics
    
    def save_current(self):
        """Save current metrics to file"""
        if self.current_metrics:
            return self.current_metrics.save_to_file(self.branch_name)
        return None
