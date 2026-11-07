"""
Reorder Findings in filtered_context.json

This script reorders findings based on different strategies to optimize
the fixing pipeline and minimize line number drift issues.

Ordering Methods:
- descending_line: Fix from bottom to top (highest line numbers first)
- ascending_line: Fix from top to bottom (lowest line numbers first)
- severity: Fix critical/high severity first
- correlated_first: Fix correlated findings first
- correlated_last: Fix correlated findings last
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List, Callable


class FindingReorderer:
    """Reorder findings in filtered_context.json"""
    
    def __init__(self, input_path: str, output_path: str = None, backup: bool = True):
        """
        Initialize reorderer
        
        Args:
            input_path: Path to filtered_context.json
            output_path: Path for output (default: overwrite input)
            backup: Create backup before overwriting
        """
        self.input_path = Path(input_path)
        self.output_path = Path(output_path) if output_path else self.input_path
        self.backup = backup
        self.context = None
    
    def load_context(self):
        """Load filtered_context.json"""
        with open(self.input_path, 'r', encoding='utf-8') as f:
            self.context = json.load(f)
        print(f"✓ Loaded {len(self.context['findings'])} findings from {self.input_path}")
    
    def save_context(self):
        """Save reordered context"""
        # Create backup if overwriting
        if self.backup and self.output_path == self.input_path:
            backup_path = self.input_path.with_suffix('.json.bak')
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(self.context, f, indent=2)
            print(f"✓ Backup saved to {backup_path}")
        
        # Save reordered context
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(self.context, f, indent=2)
        print(f"✓ Reordered findings saved to {self.output_path}")
    
    def reorder_findings(self, method: str):
        """
        Reorder findings using specified method
        
        Args:
            method: Ordering method name
        """
        if not self.context:
            raise ValueError("Context not loaded. Call load_context() first.")
        
        findings = self.context['findings']
        original_count = len(findings)
        
        # Get ordering function
        order_func = self._get_ordering_function(method)
        
        # Sort findings
        print(f"\n📊 Reordering {len(findings)} findings using '{method}' method...")
        sorted_findings = sorted(findings, key=order_func)
        
        # Reassign finding numbers
        for idx, finding in enumerate(sorted_findings, start=1):
            old_number = finding.get('finding_number', 'N/A')
            new_number = f"FINDING {idx:03d}"
            finding['finding_number'] = new_number
            
            # Print mapping for first few and last few
            if idx <= 5 or idx > len(sorted_findings) - 5:
                line = self._get_line_number(finding)
                severity = finding.get('baseline_severity', 'unknown')
                rule_id = finding.get('sast', {}).get('rule_id', 'N/A')
                print(f"  {old_number} → {new_number}: Line {line} | {severity} | {rule_id}")
            elif idx == 6:
                print(f"  ... ({len(sorted_findings) - 10} more findings) ...")
        
        self.context['findings'] = sorted_findings
        
        # Add reordering metadata
        if 'reordering_applied' not in self.context:
            self.context['reordering_applied'] = {}
        
        self.context['reordering_applied'] = {
            'method': method,
            'original_count': original_count,
            'reordered_count': len(sorted_findings)
        }
        
        print(f"\n✓ Reordering complete!")
    
    def _get_ordering_function(self, method: str) -> Callable:
        """Get sorting key function for specified method"""
        ordering_methods = {
            'descending_line': self._order_descending_line,
            'ascending_line': self._order_ascending_line,
            'severity': self._order_severity,
            'correlated_first': self._order_correlated_first,
            'correlated_last': self._order_correlated_last,
        }
        
        if method not in ordering_methods:
            available = ', '.join(ordering_methods.keys())
            raise ValueError(f"Unknown ordering method: {method}. Available: {available}")
        
        return ordering_methods[method]
    
    def _get_line_number(self, finding: Dict) -> int:
        """Extract line number from finding"""
        sast_info = finding.get('sast', {}) or {}
        location = sast_info.get('location', {}) or {}
        return location.get('start_line', 0)
    
    def _get_severity_rank(self, finding: Dict) -> int:
        """Get numeric rank for severity (lower = higher priority)"""
        severity_map = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'unknown': 4
        }
        severity = finding.get('baseline_severity', 'unknown').lower()
        return severity_map.get(severity, 4)
    
    # === Ordering Methods ===
    
    def _order_descending_line(self, finding: Dict) -> int:
        """
        Order by descending line number (highest line first)
        
        Strategy: Fix from bottom to top to minimize line drift.
        When you fix issues at higher line numbers first, changes won't
        affect the line numbers of vulnerabilities earlier in the file.
        """
        line = self._get_line_number(finding)
        # Return negative to sort descending
        return -line if line else float('inf')
    
    def _order_ascending_line(self, finding: Dict) -> int:
        """
        Order by ascending line number (lowest line first)
        
        Strategy: Fix from top to bottom.
        Warning: Changes at earlier lines will shift later line numbers.
        """
        line = self._get_line_number(finding)
        return line if line else float('inf')
    
    def _order_severity(self, finding: Dict) -> tuple:
        """
        Order by severity (critical → high → medium → low)
        
        Strategy: Fix most critical issues first.
        Secondary sort by line number (descending) to minimize drift.
        """
        severity_rank = self._get_severity_rank(finding)
        line = self._get_line_number(finding)
        return (severity_rank, -line if line else float('inf'))
    
    def _order_correlated_first(self, finding: Dict) -> tuple:
        """
        Order correlated findings first, then by severity
        
        Strategy: Fix issues detected by both SAST and DAST first
        (higher confidence of exploitability).
        """
        is_correlated = 1 if finding.get('correlation_group') else 0
        severity_rank = self._get_severity_rank(finding)
        line = self._get_line_number(finding)
        return (is_correlated, severity_rank, -line if line else float('inf'))
    
    def _order_correlated_last(self, finding: Dict) -> tuple:
        """
        Order correlated findings last
        
        Strategy: Fix SAST-only findings first (simpler), 
        save complex correlated issues for last.
        """
        is_correlated = 0 if finding.get('correlation_group') else 1
        severity_rank = self._get_severity_rank(finding)
        line = self._get_line_number(finding)
        return (is_correlated, severity_rank, -line if line else float('inf'))
    
    def print_preview(self):
        """Preview the reordering without saving"""
        if not self.context:
            raise ValueError("Context not loaded. Call load_context() first.")
        
        findings = self.context['findings']
        print(f"\n📋 Current Order Preview:")
        print(f"{'Finding':<15} {'Line':<8} {'Severity':<10} {'Rule ID':<30}")
        print("="*70)
        
        for finding in findings[:10]:
            finding_num = finding.get('finding_number', 'N/A')
            line = self._get_line_number(finding)
            severity = finding.get('baseline_severity', 'unknown')
            rule_id = finding.get('sast', {}).get('rule_id', 'N/A')
            print(f"{finding_num:<15} {line:<8} {severity:<10} {rule_id:<30}")
        
        if len(findings) > 10:
            print(f"... ({len(findings) - 10} more findings)")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Reorder findings in filtered_context.json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ordering Methods:
  descending_line    Fix from bottom to top (minimizes line drift)
  ascending_line     Fix from top to bottom
  severity           Fix critical/high severity first
  correlated_first   Fix correlated findings first
  correlated_last    Fix correlated findings last

Examples:
  # Reorder by descending line (recommended)
  python reorder_findings.py descending_line

  # Preview without saving
  python reorder_findings.py descending_line --preview

  # Specify custom paths
  python reorder_findings.py severity -i ../artifacts/filtered_context.json

  # Save to different file (keep original)
  python reorder_findings.py descending_line -o ../artifacts/filtered_context_reordered.json
        """
    )
    
    parser.add_argument(
        'method',
        choices=['descending_line', 'ascending_line', 'severity', 'correlated_first', 'correlated_last'],
        help='Ordering method to use'
    )
    
    parser.add_argument(
        '-i', '--input',
        default='../artifacts/filtered_context.json',
        help='Path to input filtered_context.json (default: ../artifacts/filtered_context.json)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Path to output file (default: overwrite input)'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Do not create backup when overwriting'
    )
    
    parser.add_argument(
        '--preview',
        action='store_true',
        help='Preview reordering without saving'
    )
    
    args = parser.parse_args()
    
    # Resolve paths relative to script location
    script_dir = Path(__file__).parent
    input_path = script_dir / args.input
    output_path = (script_dir / args.output) if args.output else None
    
    if not input_path.exists():
        print(f"❌ Error: Input file not found: {input_path}")
        return 1
    
    # Initialize reorderer
    reorderer = FindingReorderer(
        input_path=str(input_path),
        output_path=str(output_path) if output_path else None,
        backup=not args.no_backup
    )
    
    # Load context
    reorderer.load_context()
    
    if args.preview:
        print("\n📋 Original order:")
        reorderer.print_preview()
        
        # Create temporary copy for preview
        reorderer.reorder_findings(args.method)
        print("\n📋 After reordering:")
        reorderer.print_preview()
        
        print("\n⚠️  Preview mode - no files were modified")
    else:
        # Reorder and save
        reorderer.reorder_findings(args.method)
        reorderer.save_context()
        
        print(f"\n✅ Success! Run the fix pipeline to process findings in new order.")


if __name__ == '__main__':
    import sys
    sys.exit(main() or 0)
