"""
Pytest Validator

Runs pytest on repository with coverage collection (non-blocking mode).
Test failures never prevent fixes from being committed — only coverage
metrics are collected.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Tuple, Dict


class PytestValidator:
    """Runs pytest with coverage; results are recorded for metrics only
    and never cause fix failures (non-blocking)."""
    
    def __init__(self):
        pass
    
    def validate(self, repo_path: str) -> Tuple[bool, Dict]:
        """
        Run pytest with coverage on repository.
        
        Args:
            repo_path: Repository root path
        
        Returns:
            (passed: bool, results: Dict)
            results always contains 'coverage_percent' (float | None)
        """
        try:
            result = subprocess.run(
                [
                    sys.executable, '-m', 'pytest', '-v', '--tb=short',
                    '--cov=.', '--cov-report=json',
                    '-m', 'not network',
                ],
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=300
            )
            
            output = result.stdout + result.stderr
            passed = result.returncode == 0
            
            # Count passed/failed
            import re
            passed_match = re.search(r'(\d+) passed', output)
            failed_match = re.search(r'(\d+) failed', output)
            
            passed_count = int(passed_match.group(1)) if passed_match else 0
            failed_count = int(failed_match.group(1)) if failed_match else 0
            
            # Extract coverage percentage from coverage.json
            coverage_percent = None
            try:
                coverage_file = Path(repo_path) / 'coverage.json'
                if coverage_file.exists():
                    with open(coverage_file, 'r', encoding='utf-8') as f:
                        cov_data = json.load(f)
                    raw = cov_data.get('totals', {}).get('percent_covered')
                    if raw is not None:
                        coverage_percent = round(float(raw), 2)
            except Exception:
                pass  # coverage extraction is best-effort
            
            return passed, {
                'passed': passed,
                'passed_count': passed_count,
                'failed_count': failed_count,
                'coverage_percent': coverage_percent,
                'output': output,
                'return_code': result.returncode
            }
        
        except subprocess.TimeoutExpired:
            return False, {'error': 'Pytest timeout', 'passed': False, 'coverage_percent': None}
        except FileNotFoundError:
            return False, {'error': 'Pytest not installed', 'passed': False, 'coverage_percent': None}
        except Exception as e:
            return False, {'error': str(e), 'passed': False, 'coverage_percent': None}
    
    def format_failure_message(self, results: Dict) -> str:
        """Format pytest result for informational logging (not fed back to LLM)."""
        if 'error' in results:
            return f"Pytest Error: {results['error']}"
        
        output = results.get('output', '')
        failed_count = results.get('failed_count', 0)
        coverage_percent = results.get('coverage_percent')
        
        lines = output.split('\n')
        failure_lines = []
        in_failure = False
        
        for line in lines:
            if 'FAILED' in line or 'ERROR' in line:
                in_failure = True
            if in_failure:
                failure_lines.append(line)
                if len(failure_lines) > 30:
                    break
        
        failure_summary = '\n'.join(failure_lines[:30])
        coverage_line = f"Coverage: {coverage_percent:.1f}%" if coverage_percent is not None else "Coverage: unavailable"
        
        return f"""Pytest: {failed_count} test(s) failing ({coverage_line})

Test Output:
{failure_summary}
"""
