"""
Pipeline Evaluation System
Generates comprehensive metrics report for vulnerability remediation pipeline
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class PipelineEvaluator:
    """
    Evaluates pipeline performance across multiple dimensions:
    - Vulnerability fix rate (SAST verified)
    - Token usage and cost
    - Efficiency (tokens per successful fix)
    - Code minimality
    - Test coverage change
    - Fix duration
    - SAST alert delta
    - New vulnerability introduction
    """
    
    def __init__(self, reports_dir: Path, branch_name: str):
        self.reports_dir = reports_dir
        self.branch_name = branch_name
        self.branch_reports_dir = reports_dir / branch_name
        
        # Calculate project root (parent of llm/)
        self.project_root = Path(__file__).parent.parent
        
        # Load data sources
        self.metrics = self._load_metrics()
        self.summaries = self._load_summaries()
        self.original_context = self._load_json(self.project_root / "artifacts" / "context.json")
        self.filtered_context = self._load_json(self.project_root / "artifacts" / "filtered_context.json")
        self.baseline_coverage = self._load_json(self.project_root / "artifacts" / "baseline_coverage.json")
        self.new_coverage = self._load_json(self.branch_reports_dir / "coverage_after_fixes.json")
        self.sarif_comparison = self._load_json(self.branch_reports_dir / "sarif_comparison.json")
        
    def _load_json(self, path: Path) -> Optional[Dict]:
        """Load JSON file safely"""
        try:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load {path}: {e}")
        return None
    
    def _load_metrics(self) -> Optional[Dict]:
        """Load metrics.json from branch reports"""
        return self._load_json(self.branch_reports_dir / "metrics.json")
    
    def _load_summaries(self) -> Optional[Dict]:
        """Load summaries.json from branch reports"""
        return self._load_json(self.branch_reports_dir / "summaries.json")
    
    def calculate_fix_rate(self) -> Dict[str, Any]:
        """
        Calculate SAST-verified fix rate
        
        Success = vulnerability no longer detected in SAST scan
        Based on findings actually attempted, not all available findings
        """
        if not self.metrics:
            return {
                "error": "Missing required data",
                'total_findings_available': 0,
                'total_findings_attempted': 0,
                'sast_verified_fixes': 0,
                'failed_fixes': 0,
                'sast_verified_rate_percent': 0
            }
        
        summary = self.metrics.get('summary', {})
        
        # Use actual attempted findings from metrics, not all filtered findings
        attempted = summary.get('total_findings', 0)
        sast_verified = summary.get('sast_verified_fixes', 0)
        failed = attempted - sast_verified
        rate = summary.get('sast_verified_rate', 0)
        
        # Get context counts for reference
        total_available = len(self.filtered_context.get('findings', [])) if self.filtered_context else 0
        
        return {
            'total_findings_available': total_available,
            'total_findings_attempted': attempted,
            'sast_verified_fixes': sast_verified,
            'failed_fixes': failed,
            'sast_verified_rate_percent': round(rate, 2)
        }
    
    def calculate_token_usage(self) -> Dict[str, Any]:
        """Calculate average token usage per finding"""
        if not self.metrics:
            return {"error": "Missing metrics data"}
        
        summary = self.metrics.get('summary', {})
        
        return {
            'total_tokens': summary.get('total_tokens', 0),
            'average_per_finding': round(summary.get('average_tokens_per_finding', 0), 2),
            'total_prompt_tokens': sum(
                f.get('api_usage', {}).get('prompt_tokens', 0) 
                for f in self.metrics.get('findings', [])
            ),
            'total_completion_tokens': sum(
                f.get('api_usage', {}).get('completion_tokens', 0)
                for f in self.metrics.get('findings', [])
            )
        }
    
    def calculate_efficiency_score(self, fix_rate_data: Dict, token_data: Dict) -> Dict[str, Any]:
        """
        Calculate efficiency: tokens per successful fix
        
        Lower is better - indicates cost-effectiveness
        """
        total_tokens = token_data.get('total_tokens', 0)
        sast_verified = fix_rate_data.get('sast_verified_fixes', 0)
        
        if sast_verified == 0:
            return {
                'tokens_per_successful_fix': 0,
                'efficiency_grade': 'N/A',
                'assessment': 'No successful fixes to evaluate'
            }
        
        efficiency = total_tokens / sast_verified
        
        # Grade the efficiency
        if efficiency < 7000:
            grade = 'A'
            assessment = 'Highly efficient - production-ready'
        elif efficiency < 12000:
            grade = 'B'
            assessment = 'Acceptable - monitor for improvements'
        elif efficiency < 20000:
            grade = 'C'
            assessment = 'Concerning - optimization needed'
        else:
            grade = 'D'
            assessment = 'Inefficient - requires immediate attention'
        
        return {
            'tokens_per_successful_fix': round(efficiency, 2),
            'efficiency_grade': grade,
            'assessment': assessment
        }
    
    def calculate_code_minimality(self) -> Dict[str, Any]:
        """Calculate code change statistics"""
        if not self.metrics:
            return {"error": "Missing metrics data"}
        
        findings = self.metrics.get('findings', [])
        total_added = sum(f.get('code_changes', {}).get('lines_added', 0) for f in findings)
        total_removed = sum(f.get('code_changes', {}).get('lines_removed', 0) for f in findings)
        
        # Collect all files modified
        files_set = set()
        for finding in findings:
            files_set.update(finding.get('code_changes', {}).get('files_modified', []))
        
        total_churn = total_added + total_removed
        net_change = total_added - total_removed
        
        successful_fixes = sum(1 for f in findings if f.get('outcome', {}).get('fix_success'))
        avg_churn = (total_churn / successful_fixes) if successful_fixes > 0 else 0
        
        return {
            'total_lines_added': total_added,
            'total_lines_removed': total_removed,
            'total_churn': total_churn,
            'net_change': net_change,
            'average_churn_per_fix': round(avg_churn, 2),
            'minimality_score': round(avg_churn, 2),
            'files_modified_count': len(files_set),
            'files_modified': sorted(list(files_set))
        }
    
    def calculate_coverage_change(self) -> Dict[str, Any]:
        """Calculate test coverage delta between baseline and after fixes"""
        if not self.baseline_coverage or not self.new_coverage:
            return {
                'measured': False,
                'reason': 'Coverage data not available'
            }
        
        baseline = self.baseline_coverage.get('totals', {}).get('percent_covered', 0)
        new = self.new_coverage.get('totals', {}).get('percent_covered', 0)
        delta = new - baseline
        
        return {
            'measured': True,
            'baseline_coverage_percent': baseline,
            'new_coverage_percent': new,
            'coverage_delta_percent': delta,
            'coverage_improved': delta > 0,
            'coverage_delta_display': f"{'+' if delta >= 0 else ''}{delta:.2f}%"
        }
    
    def calculate_fix_duration(self) -> Dict[str, Any]:
        """Calculate average fix duration per vulnerability"""
        if not self.metrics:
            return {"error": "Missing metrics data"}
        
        summary = self.metrics.get('summary', {})
        findings = self.metrics.get('findings', [])
        
        durations = [f.get('timing', {}).get('duration_seconds', 0) for f in findings]
        durations = [d for d in durations if d > 0]  # Filter out zeros
        
        return {
            'total_duration_seconds': round(summary.get('total_duration_seconds', 0), 2),
            'average_per_finding_seconds': round(summary.get('average_duration_per_finding', 0), 2),
            'fastest_fix_seconds': round(min(durations), 2) if durations else 0,
            'slowest_fix_seconds': round(max(durations), 2) if durations else 0
        }
    
    def calculate_sast_delta(self, sarif_comparison: Dict) -> Dict[str, Any]:
        """
        Calculate SAST alert delta
        
        Focus on targeted findings, not all alerts (due to line shift issues)
        
        Args:
            sarif_comparison: Enhanced comparison data from github_integration.py
        """
        if not sarif_comparison:
            return {
                'measured': False,
                'reason': 'SARIF comparison data not available'
            }
        
        alert_counts = sarif_comparison.get('alert_counts', {})
        fix_rate_data = self.calculate_fix_rate()
        
        # Use targeted counts instead of all alerts (more accurate due to line shifts)
        targeted_count = alert_counts.get('targeted_count', 0)
        targeted_fixed = alert_counts.get('targeted_fixed', 0)
        targeted_still_present = alert_counts.get('targeted_still_present', 0)
        
        reduction_percent = (targeted_fixed / targeted_count * 100) if targeted_count > 0 else 0
        
        # Also include overall alert counts for reference
        original_total = alert_counts.get('original_total', 0)
        new_total = alert_counts.get('new_total', 0)
        net_reduction = original_total - new_total
        
        return {
            'measured': True,
            # Targeted metrics (most accurate)
            'targeted_findings_count': targeted_count,
            'targeted_fixed': targeted_fixed,
            'targeted_still_present': targeted_still_present,
            'targeted_reduction_percent': round(reduction_percent, 2),
            # Overall metrics (affected by line shifts)
            'original_total_alerts': original_total,
            'new_total_alerts': new_total,
            'overall_net_reduction': net_reduction,
            'note': 'Overall alert counts may be affected by line number shifts after code changes'
        }
    
    def calculate_new_vuln_rate(self, sarif_comparison: Dict) -> Dict[str, Any]:
        """
        Calculate new vulnerability introduction rate
        
        Note: May include false positives due to line number shifts
        """
        if not sarif_comparison:
            return {
                'measured': False,
                'reason': 'SARIF comparison data not available'
            }
        
        new_vulns = sarif_comparison.get('new_vulnerabilities', [])
        fix_rate_data = self.calculate_fix_rate()
        attempted = fix_rate_data.get('total_findings_attempted', 0)
        
        new_count = len(new_vulns)
        rate = (new_count / attempted * 100) if attempted > 0 else 0
        
        return {
            'measured': True,
            'new_vulnerabilities_count': new_count,
            'introduction_rate_percent': round(rate, 2),
            'new_vulnerabilities': new_vulns,
            'note': 'May include false positives due to line number shifts after code changes'
        }
    
    def generate_evaluation(self, sarif_comparison: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate complete evaluation report
        
        Args:
            sarif_comparison: Enhanced SARIF comparison data with alert counts
                            If None, will use the loaded sarif_comparison from file
        """
        # Use provided sarif_comparison or fall back to loaded one
        if sarif_comparison is not None:
            self.sarif_comparison = sarif_comparison
        # else: use self.sarif_comparison loaded from file in __init__
        
        # Calculate all metrics
        fix_rate = self.calculate_fix_rate()
        token_usage = self.calculate_token_usage()
        efficiency = self.calculate_efficiency_score(fix_rate, token_usage)
        code_minimality = self.calculate_code_minimality()
        coverage = self.calculate_coverage_change()
        duration = self.calculate_fix_duration()
        sast_delta = self.calculate_sast_delta(self.sarif_comparison)
        new_vuln_rate = self.calculate_new_vuln_rate(self.sarif_comparison)
        
        # Generate overall assessment
        assessment = self._generate_assessment(
            fix_rate, efficiency, new_vuln_rate, coverage
        )
        
        evaluation = {
            'branch': self.branch_name,
            'evaluated_at': datetime.now().isoformat(),
            'metrics': {
                'vulnerability_fix_rate': fix_rate,
                'token_usage': token_usage,
                'efficiency_score': efficiency,
                'code_minimality': code_minimality,
                'test_coverage_change': coverage,
                'fix_duration': duration,
                'sast_alert_delta': sast_delta,
                'dast_alert_delta': {
                    'measured': False,
                    'reason': 'DAST not re-run in pipeline'
                },
                'new_vulnerability_introduction': new_vuln_rate
            },
            'overall_assessment': assessment
        }
        
        return evaluation
    
    def _generate_assessment(self, fix_rate: Dict, efficiency: Dict, 
                            new_vuln: Dict, coverage: Dict) -> Dict[str, Any]:
        """Generate overall grade and assessment"""
        # Calculate grade based on key metrics
        fix_rate_pct = fix_rate.get('sast_verified_rate_percent', 0)
        efficiency_grade = efficiency.get('efficiency_grade', 'D')
        new_vuln_rate = new_vuln.get('introduction_rate_percent', 100) if new_vuln.get('measured') else 0
        coverage_improved = coverage.get('coverage_improved', False) if coverage.get('measured') else None
        
        # Grade calculation
        grade_points = 0
        
        # Fix rate (40 points)
        if fix_rate_pct >= 90:
            grade_points += 40
        elif fix_rate_pct >= 70:
            grade_points += 30
        elif fix_rate_pct >= 50:
            grade_points += 20
        else:
            grade_points += 10
        
        # Efficiency (30 points)
        if efficiency_grade == 'A':
            grade_points += 30
        elif efficiency_grade == 'B':
            grade_points += 20
        elif efficiency_grade == 'C':
            grade_points += 10
        
        # Safety (20 points)
        if new_vuln_rate == 0:
            grade_points += 20
        elif new_vuln_rate < 5:
            grade_points += 15
        elif new_vuln_rate < 10:
            grade_points += 5
        
        # Coverage (10 points)
        if coverage_improved is True:
            grade_points += 10
        elif coverage_improved is False:
            grade_points += 5
        elif coverage_improved is None:
            grade_points += 7  # Neutral if not measured
        
        # Convert to letter grade
        if grade_points >= 90:
            overall_grade = 'A'
        elif grade_points >= 80:
            overall_grade = 'B'
        elif grade_points >= 70:
            overall_grade = 'C'
        elif grade_points >= 60:
            overall_grade = 'D'
        else:
            overall_grade = 'F'
        
        # Production readiness
        production_ready = (
            fix_rate_pct >= 80 and
            new_vuln_rate < 5 and
            efficiency_grade in ['A', 'B']
        )
        
        # Recommendations
        recommendations = []
        if fix_rate_pct < 80:
            recommendations.append("Improve fix rate through better prompts or validation")
        if efficiency_grade in ['C', 'D']:
            recommendations.append("Optimize token usage - review context selection")
        if new_vuln_rate > 5:
            recommendations.append("High new vulnerability rate - review fix safety")
        if coverage_improved is False:
            recommendations.append("Coverage declined - verify test health")
        
        return {
            'grade': overall_grade,
            'grade_points': grade_points,
            'production_ready': production_ready,
            'recommendations': recommendations
        }
    
    def save_evaluation(self, output_path: Optional[Path] = None) -> Path:
        """
        Save evaluation report to JSON file
        
        Args:
            output_path: Custom path, defaults to reports/{branch}/evaluation.json
        """
        if output_path is None:
            output_path = self.branch_reports_dir / "evaluation.json"
        
        evaluation = self.generate_evaluation(self.sarif_comparison)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(evaluation, f, indent=2)
        
        return output_path
    
    def print_summary(self, evaluation: Optional[Dict] = None):
        """Print human-readable evaluation summary"""
        if evaluation is None:
            evaluation = self.generate_evaluation(self.sarif_comparison)
        
        metrics = evaluation['metrics']
        assessment = evaluation['overall_assessment']
        
        print("\n" + "="*70)
        print("📊 PIPELINE EVALUATION REPORT")
        print("="*70)
        
        # Effectiveness
        print("\n🎯 Effectiveness:")
        fix_rate = metrics['vulnerability_fix_rate']
        if 'error' not in fix_rate:
            attempted = fix_rate['total_findings_attempted']
            verified = fix_rate['sast_verified_fixes']
            rate = fix_rate['sast_verified_rate_percent']
            available = fix_rate['total_findings_available']
            print(f"  ✅ SAST Verified Rate: {rate}% ({verified}/{attempted} attempted, {available} available)")
        else:
            print(f"  ⚠️  Fix rate: {fix_rate['error']}")
        
        if metrics['sast_alert_delta'].get('measured'):
            sast = metrics['sast_alert_delta']
            print(f"  📉 SAST Targeted Reduction: {sast['targeted_reduction_percent']}% "
                  f"({sast['targeted_fixed']}/{sast['targeted_findings_count']} fixed)")
            if sast.get('overall_net_reduction', 0) != sast.get('targeted_fixed', 0):
                print(f"     Note: Overall count affected by line shifts (net {sast['overall_net_reduction']})")
        
        # Efficiency
        print("\n⚡ Efficiency:")
        eff = metrics['efficiency_score']
        if 'error' not in eff:
            print(f"  💰 Efficiency Score: {eff['tokens_per_successful_fix']:.0f} tokens/fix [Grade {eff['efficiency_grade']}]")
        else:
            print(f"  ⚠️  Efficiency: {eff['assessment']}")
        
        token = metrics['token_usage']
        if 'error' not in token:
            print(f"  🔢 Avg Token Usage: {token['average_per_finding']:.0f} tokens/attempt")
        
        dur = metrics['fix_duration']
        if 'error' not in dur:
            print(f"  ⏱️  Avg Fix Duration: {dur['average_per_finding_seconds']:.1f}s per vulnerability")
        
        # Quality
        print("\n✨ Quality:")
        minimal = metrics['code_minimality']
        if 'error' not in minimal:
            print(f"  📝 Code Minimality: {minimal['minimality_score']:.1f} lines/fix (surgical)")
            print(f"     +{minimal['total_lines_added']} / -{minimal['total_lines_removed']} lines")
        
        if metrics['test_coverage_change'].get('measured'):
            cov = metrics['test_coverage_change']
            print(f"  🧪 Coverage Change: {cov['coverage_delta_display']}")
        else:
            print(f"  🧪 Coverage Change: Not measured")
        
        # Safety
        print("\n🛡️  Safety:")
        new_vuln = metrics['new_vulnerability_introduction']
        if new_vuln.get('measured'):
            count = new_vuln['new_vulnerabilities_count']
            rate = new_vuln['introduction_rate_percent']
            print(f"  ⚠️  New Vulnerabilities: {count} ({rate}%)")
            if count > 0:
                print(f"     Note: May include false positives due to line number shifts")
        else:
            print(f"  ⚠️  New Vulnerabilities: Not measured")
        
        # Overall
        print(f"\n📊 Overall Grade: {assessment['grade']}")
        print(f"🚀 Production Ready: {'Yes' if assessment['production_ready'] else 'No'}")
        
        if assessment['recommendations']:
            print("\n💡 Recommendations:")
            for rec in assessment['recommendations']:
                print(f"  • {rec}")
        
        print("="*70)
