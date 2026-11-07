"""
Pylint Validator

Runs pylint on changed files and returns score
"""

import subprocess
import re
import sys
from pathlib import Path
from typing import Tuple, Dict


class PylintValidator:
    """Validates code using pylint"""
    
    def __init__(self, min_score: float = 2.0):
        """
        Initialize pylint validator
        
        Args:
            min_score: Minimum acceptable pylint score
        """
        self.min_score = min_score
    
    def validate(self, file_path: str, repo_path: str) -> Tuple[bool, Dict]:
        """
        Run pylint on file
        
        Args:
            file_path: Relative file path
            repo_path: Repository root path
        
        Returns:
            (passed: bool, results: Dict)
        """
        full_path = Path(repo_path) / file_path
        
        if not full_path.exists():
            return False, {'error': f'File not found: {full_path}'}
        
        # Run pylint
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pylint', str(full_path), '--output-format=text'],
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=60
            )
            
            output = result.stdout + result.stderr
            
            # Extract score
            score_match = re.search(r'Your code has been rated at ([\-0-9.]+)/10', output)
            score = float(score_match.group(1)) if score_match else 0.0
            
            passed = score >= self.min_score
            
            return passed, {
                'score': score,
                'min_score': self.min_score,
                'output': output,
                'passed': passed
            }
        
        except subprocess.TimeoutExpired:
            return False, {'error': 'Pylint timeout', 'passed': False}
        except FileNotFoundError:
            return False, {'error': 'Pylint not installed', 'passed': False}
        except Exception as e:
            return False, {'error': str(e), 'passed': False}
    
    def format_failure_message(self, results: Dict) -> str:
        """
        Format pylint failure for LLM feedback
        
        Args:
            results: Validation results
        
        Returns:
            Formatted error message
        """
        if 'error' in results:
            return f"Pylint Error: {results['error']}"
        
        score = results.get('score', 0.0)
        output = results.get('output', '')
        
        # Extract relevant errors (first 10 lines)
        lines = output.split('\n')
        error_lines = [line for line in lines if line.strip() and not line.startswith('*****')]
        error_summary = '\n'.join(error_lines[:15])
        
        return f"""Pylint Score: {score:.2f}/10.00 (Minimum: {self.min_score})

Pylint Output:
{error_summary}

⚠️ Focus on fixing syntax errors and undefined variables.
⚠️ Ignore errors about variables defined elsewhere in the file.
"""
