"""
Generate consolidated results JSON from a run folder.

Extracts key metrics from various JSON files in the run folder and
creates a single, minimal results JSON file.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any


def extract_baseline_pylint_score(console_log_path: Path) -> Optional[float]:
    """Extract baseline pylint score from console.log"""
    try:
        with open(console_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
            match = re.search(r'Baseline pylint score: ([\d.]+)/10\.00', content)
            if match:
                return float(match.group(1))
    except Exception as e:
        print(f"Warning: Could not extract baseline pylint score: {e}")
    return None


def extract_pylint_scores(metrics_path: Path, summaries_path: Path, 
                         baseline_score: Optional[float]) -> Dict[str, float]:
    """Extract pylint scores for each finding"""
    scores = {}
    
    if baseline_score is not None:
        scores['baseline'] = baseline_score
    
    try:
        with open(metrics_path, 'r', encoding='utf-8') as f:
            metrics = json.load(f)
        
        with open(summaries_path, 'r', encoding='utf-8') as f:
            summaries = json.load(f)
        
        # Map finding IDs to finding numbers and CWEs
        finding_map = {}
        for finding in summaries.get('findings', []):
            finding_map[finding['finding_id']] = {
                'finding_number': finding['finding_number'],
                'cwe': finding['cwe']
            }
        
        # Extract pylint scores from metrics
        for finding in metrics.get('findings', []):
            finding_id = finding['finding_info']['finding_id']
            pylint_score = finding['validation_results'].get('final_pylint_score')
            
            if finding_id in finding_map and pylint_score is not None:
                info = finding_map[finding_id]
                key = f"{info['finding_number']} ({info['cwe']})"
                scores[key] = pylint_score
    
    except Exception as e:
        print(f"Warning: Could not extract pylint scores: {e}")
    
    return scores


def extract_finding_details_from_summaries(summaries_path: Path) -> Dict[str, Dict]:
    """Create a map of finding_id to finding details"""
    finding_details = {}
    
    try:
        with open(summaries_path, 'r', encoding='utf-8') as f:
            summaries = json.load(f)
        
        for finding in summaries.get('findings', []):
            finding_details[finding['finding_id']] = {
                'finding_number': finding['finding_number'],
                'rule_id': finding['finding_id'],
                'cwe': finding['cwe'],
                'severity': finding['severity']
            }
    except Exception as e:
        print(f"Warning: Could not extract finding details: {e}")
    
    return finding_details


def process_sast_alerts(evaluation_path: Path, sarif_comparison_path: Path,
                       summaries_path: Path) -> Dict[str, Any]:
    """Process SAST alert reduction and new alerts"""
    result = {
        'measured': True,
        'before_count': 0,
        'after_count': 0,
        'net_reduction': 0,
        'reduction_percent': 0.0,
        'fixed': {'count': 0, 'findings': []},
        'still_present': {'count': 0, 'findings': []}
    }
    
    try:
        with open(evaluation_path, 'r', encoding='utf-8') as f:
            evaluation = json.load(f)
        
        with open(sarif_comparison_path, 'r', encoding='utf-8') as f:
            sarif_comparison = json.load(f)
        
        # Get finding details
        finding_details = extract_finding_details_from_summaries(summaries_path)
        
        # Extract alert counts
        sast_delta = evaluation['metrics']['sast_alert_delta']
        result['before_count'] = sast_delta['targeted_findings_count']
        result['after_count'] = sast_delta['targeted_still_present']
        result['net_reduction'] = sast_delta['targeted_fixed']
        result['reduction_percent'] = sast_delta['targeted_reduction_percent']
        
        # Process validation results
        validation_results = sarif_comparison.get('validation_results', {})
        
        for finding_id, validation in validation_results.items():
            # Extract rule_id from finding_id (format: sast-py/flask-debug-vulnerable_app.py:507)
            # Remove 'sast-' prefix and extract the rule part before the file name
            if finding_id.startswith('sast-'):
                remainder = finding_id[5:]  # Remove 'sast-' -> 'py/flask-debug-vulnerable_app.py:507'
                # Extract everything before -vulnerable_app.py or before the filename
                # The rule_id is everything before the last occurrence of '-' followed by filename
                if '-vulnerable_app.py' in remainder:
                    rule_id = remainder.split('-vulnerable_app.py')[0]
                else:
                    # Fallback: try to extract py/rule-name pattern
                    parts = remainder.split('-')
                    if len(parts) >= 2:
                        rule_id = '/'.join(parts[:2])  # py/flask, py/stack, etc.
                    else:
                        rule_id = remainder
            else:
                rule_id = finding_id
            
            if rule_id and rule_id in finding_details:
                details = finding_details[rule_id]
                
                if validation['validated']:
                    result['fixed']['findings'].append(details)
                else:
                    result['still_present']['findings'].append(details)
        
        result['fixed']['count'] = len(result['fixed']['findings'])
        result['still_present']['count'] = len(result['still_present']['findings'])
    
    except Exception as e:
        print(f"Warning: Could not process SAST alerts: {e}")
        result['measured'] = False
    
    return result


def compare_dast_alerts(baseline_dast_path: Path, new_dast_path: Path) -> Dict[str, Any]:
    """Compare DAST reports to calculate reduction and new alerts"""
    result = {
        'measured': False,
        'before_count': 0,
        'after_count': 0,
        'net_reduction': 0,
        'reduction_percent': 0.0,
        'fixed': {'count': 0, 'alerts': []},
        'still_present': {'count': 0, 'alerts': []}
    }
    
    try:
        # Check if both files exist
        if not baseline_dast_path.exists() or not new_dast_path.exists():
            result['measured'] = False
            return result
        
        with open(baseline_dast_path, 'r', encoding='utf-8') as f:
            baseline_dast = json.load(f)
        
        with open(new_dast_path, 'r', encoding='utf-8') as f:
            new_dast = json.load(f)
        
        # Extract alerts from both reports
        def extract_alerts(dast_report):
            alerts = []
            for site in dast_report.get('site', []):
                for alert in site.get('alerts', []):
                    alerts.append({
                        'alert_ref': alert.get('alertRef'),
                        'alert_type': alert.get('alert'),
                        'risk': alert.get('riskdesc', '').split(' ')[0],  # Extract risk level
                        'confidence': alert.get('riskdesc', '').split('(')[-1].rstrip(')') if '(' in alert.get('riskdesc', '') else 'Unknown',
                        'pluginid': alert.get('pluginid')
                    })
            return alerts
        
        baseline_alerts = extract_alerts(baseline_dast)
        new_alerts = extract_alerts(new_dast)
        
        # Create sets for comparison (using alertRef as key)
        baseline_refs = {alert['alert_ref'] for alert in baseline_alerts}
        new_refs = {alert['alert_ref'] for alert in new_alerts}
        
        # Calculate fixed and still present
        fixed_refs = baseline_refs - new_refs
        still_present_refs = baseline_refs & new_refs
        
        result['before_count'] = len(baseline_alerts)
        result['after_count'] = len(new_alerts)
        result['net_reduction'] = len(fixed_refs)
        result['reduction_percent'] = round((len(fixed_refs) / len(baseline_alerts) * 100), 2) if baseline_alerts else 0.0
        
        # Get alert details for fixed
        result['fixed']['alerts'] = [alert for alert in baseline_alerts if alert['alert_ref'] in fixed_refs]
        result['fixed']['count'] = len(result['fixed']['alerts'])
        
        # Get alert details for still present
        result['still_present']['alerts'] = [alert for alert in new_alerts if alert['alert_ref'] in still_present_refs]
        result['still_present']['count'] = len(result['still_present']['alerts'])
        
        result['measured'] = True
    
    except Exception as e:
        print(f"Warning: Could not compare DAST alerts: {e}")
        result['measured'] = False
    
    return result


def extract_new_dast_alerts(baseline_dast_path: Path, new_dast_path: Path) -> Dict[str, Any]:
    """Extract newly introduced DAST alerts"""
    result = {
        'count': 0,
        'alerts': []
    }
    
    try:
        if not baseline_dast_path.exists() or not new_dast_path.exists():
            return result
        
        with open(baseline_dast_path, 'r', encoding='utf-8') as f:
            baseline_dast = json.load(f)
        
        with open(new_dast_path, 'r', encoding='utf-8') as f:
            new_dast = json.load(f)
        
        # Extract alert refs
        def extract_alert_refs(dast_report):
            refs = set()
            for site in dast_report.get('site', []):
                for alert in site.get('alerts', []):
                    refs.add(alert.get('alertRef'))
            return refs
        
        baseline_refs = extract_alert_refs(baseline_dast)
        
        # Find new alerts
        for site in new_dast.get('site', []):
            for alert in site.get('alerts', []):
                alert_ref = alert.get('alertRef')
                if alert_ref not in baseline_refs:
                    result['alerts'].append({
                        'alert_type': alert.get('alert'),
                        'alert_ref': alert_ref,
                        'risk': alert.get('riskdesc', '').split(' ')[0],
                        'confidence': alert.get('riskdesc', '').split('(')[-1].rstrip(')') if '(' in alert.get('riskdesc', '') else 'Unknown',
                        'note': 'Introduced during fix'
                    })
        
        result['count'] = len(result['alerts'])
    
    except Exception as e:
        print(f"Warning: Could not extract new DAST alerts: {e}")
    
    return result


def generate_results(run_folder_path: Path) -> Dict[str, Any]:
    """Generate consolidated results from a run folder"""
    
    branch_name = run_folder_path.name
    
    # File paths
    evaluation_path = run_folder_path / 'evaluation.json'
    summaries_path = run_folder_path / 'summaries.json'
    metrics_path = run_folder_path / 'metrics.json'
    sarif_comparison_path = run_folder_path / 'sarif_comparison.json'
    console_log_path = run_folder_path / 'console.log'
    baseline_dast_path = run_folder_path / 'full-scan-report.json'
    new_dast_path = run_folder_path / f'{branch_name}-dast.json'
    
    # Load evaluation data
    with open(evaluation_path, 'r', encoding='utf-8') as f:
        evaluation = json.load(f)
    
    # Extract baseline pylint score
    baseline_pylint = extract_baseline_pylint_score(console_log_path)
    
    # Build results
    results = {
        'branch': branch_name,
        'evaluated_at': evaluation.get('evaluated_at'),
        
        'vulnerability_fix_rate': {
            'attempted': evaluation['metrics']['vulnerability_fix_rate']['total_findings_attempted'],
            'fixed': evaluation['metrics']['vulnerability_fix_rate']['sast_verified_fixes'],
            'fix_rate_percent': evaluation['metrics']['vulnerability_fix_rate']['sast_verified_rate_percent']
        },
        
        'sast_alert_reduction': process_sast_alerts(evaluation_path, sarif_comparison_path, summaries_path),
        
        'dast_alert_reduction': compare_dast_alerts(baseline_dast_path, new_dast_path),
        
        'new_sast_alerts': {
            'count': evaluation['metrics']['new_vulnerability_introduction']['new_vulnerabilities_count'],
            'alerts': evaluation['metrics']['new_vulnerability_introduction']['new_vulnerabilities']
        },
        
        'new_dast_alerts': extract_new_dast_alerts(baseline_dast_path, new_dast_path),
        
        'token_efficiency': {
            'average_tokens_per_fix': evaluation['metrics']['token_usage']['average_per_finding'],
            'total_tokens': evaluation['metrics']['token_usage']['total_tokens'],
            'prompt_tokens': evaluation['metrics']['token_usage']['total_prompt_tokens'],
            'completion_tokens': evaluation['metrics']['token_usage']['total_completion_tokens']
        },
        
        'code_minimality': {
            'average_lines_changed_per_fix': evaluation['metrics']['code_minimality']['average_churn_per_fix'],
            'total_lines_added': evaluation['metrics']['code_minimality']['total_lines_added'],
            'total_lines_removed': evaluation['metrics']['code_minimality']['total_lines_removed'],
            'total_churn': evaluation['metrics']['code_minimality']['total_churn']
        },
        
        'average_fix_duration': {
            'average_seconds': evaluation['metrics']['fix_duration']['average_per_finding_seconds'],
            'total_seconds': evaluation['metrics']['fix_duration']['total_duration_seconds'],
            'fastest_seconds': evaluation['metrics']['fix_duration']['fastest_fix_seconds'],
            'slowest_seconds': evaluation['metrics']['fix_duration']['slowest_fix_seconds']
        },
        
        'pylint_scores': extract_pylint_scores(metrics_path, summaries_path, baseline_pylint),
        
        'test_coverage': {
            'before_percent': round(evaluation['metrics']['test_coverage_change']['baseline_coverage_percent'], 2),
            'after_percent': round(evaluation['metrics']['test_coverage_change']['new_coverage_percent'], 2),
            'delta_percent': round(evaluation['metrics']['test_coverage_change']['coverage_delta_percent'], 2)
        }
    }
    
    return results


def main():
    """Main function to generate results for a specific run folder"""
    
    # Test with the deepseek folder
    reports_dir = Path(__file__).parent.parent / 'reports'
    run_folder = reports_dir / 'openrouter-deepseek-v3-2-20260303-003520'
    
    if not run_folder.exists():
        print(f"Error: Run folder not found: {run_folder}")
        return
    
    print(f"Generating results for: {run_folder.name}")
    
    # Generate results
    results = generate_results(run_folder)
    
    # Save to file
    output_path = run_folder / f'{run_folder.name}_results.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"✓ Results saved to: {output_path}")
    
    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Branch: {results['branch']}")
    print(f"Fix Rate: {results['vulnerability_fix_rate']['fix_rate_percent']}%")
    print(f"SAST Reduction: {results['sast_alert_reduction']['reduction_percent']}%")
    print(f"DAST Reduction: {results['dast_alert_reduction']['reduction_percent']}%")
    print(f"Token Efficiency: {results['token_efficiency']['average_tokens_per_fix']} tokens/fix")
    print(f"Code Minimality: {results['code_minimality']['average_lines_changed_per_fix']} lines/fix")
    print(f"Avg Fix Duration: {results['average_fix_duration']['average_seconds']}s")
    print(f"Coverage Change: {results['test_coverage']['delta_percent']}%")


if __name__ == '__main__':
    main()
