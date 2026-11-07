"""
GitHub Integration for Workflow Triggering and Artifact Download
"""

import os
import time
import json
import requests
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, Optional, List
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')


class GitHubIntegration:
    """Handle GitHub API interactions"""
    
    def __init__(self, repo: str):
        """
        Initialize GitHub integration
        
        Args:
            repo: Repository in format 'owner/repo'
        """
        self.repo = repo
        self.token = os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GITHUB_TOKEN not found in environment")
        
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = f'https://api.github.com/repos/{self.repo}'
    
    def trigger_workflow(self, workflow_name: str, branch: str) -> bool:
        """
        Trigger a GitHub Actions workflow on a specific branch
        
        Args:
            workflow_name: Name of the workflow file (e.g., 'sast.yml')
            branch: Branch name to run on
            
        Returns:
            True if triggered successfully
        """
        # Get workflow ID by name
        workflows_url = f'{self.base_url}/actions/workflows'
        response = requests.get(workflows_url, headers=self.headers)
        
        if response.status_code != 200:
            print(f"    ✗ Failed to list workflows: {response.status_code}")
            return False
        
        workflows = response.json()['workflows']
        workflow_id = None
        
        for workflow in workflows:
            # Match by name or file name
            if workflow_name.lower() in workflow['name'].lower() or \
               workflow_name.lower() in workflow['path'].lower():
                workflow_id = workflow['id']
                break
        
        if not workflow_id:
            print(f"    ✗ Workflow '{workflow_name}' not found")
            return False
        
        # Trigger the workflow
        dispatch_url = f'{self.base_url}/actions/workflows/{workflow_id}/dispatches'
        payload = {
            'ref': branch
        }
        
        response = requests.post(dispatch_url, headers=self.headers, json=payload)
        
        if response.status_code == 204:
            print(f"    ✓ Workflow triggered on branch '{branch}'")
            return True
        else:
            print(f"    ✗ Failed to trigger workflow: {response.status_code}")
            return False
    
    def wait_for_workflow_completion(
        self, 
        branch: str, 
        workflow_name: str,
        timeout: int = 600,
        poll_interval: int = 5
    ) -> Optional[Dict]:
        """
        Wait for the latest workflow run to complete
        
        Args:
            branch: Branch name
            workflow_name: Workflow name to monitor
            timeout: Maximum wait time in seconds
            poll_interval: Seconds between checks
            
        Returns:
            Workflow run data if completed, None if timeout
        """
        start_time = time.time()
        target_run_id = None
        
        print(f"    ⏳ Polling for workflow completion (checking every {poll_interval}s)...")
        
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)
            
            # Get recent workflow runs for this branch
            runs_url = f'{self.base_url}/actions/runs'
            params = {
                'branch': branch,
                'per_page': 10
            }
            
            response = requests.get(runs_url, headers=self.headers, params=params)
            
            if response.status_code != 200:
                print(f"    ✗ Failed to get workflow runs: {response.status_code}")
                time.sleep(poll_interval)
                continue
            
            runs = response.json()['workflow_runs']
            
            # Find the matching workflow run (most recent one for this branch)
            matching_run = None
            for run in runs:
                # Match by workflow name
                if workflow_name.lower() in run['name'].lower():
                    # If we haven't locked onto a run yet, use the first match
                    if target_run_id is None:
                        target_run_id = run['id']
                        matching_run = run
                        print(f"    🔍 Tracking workflow run #{run['id']} (started: {run['created_at']})")
                        break
                    # If we have a target, only check that specific run
                    elif run['id'] == target_run_id:
                        matching_run = run
                        break
            
            if matching_run:
                status = matching_run['status']
                conclusion = matching_run.get('conclusion')
                
                if status == 'completed':
                    print(f"\n    ✓ Workflow completed after {elapsed}s: {conclusion}")
                    return matching_run
                else:
                    print(f"    ⏳ {elapsed}s elapsed - Status: {status}...", end='\r')
            else:
                print(f"    ⏳ {elapsed}s elapsed - Waiting for workflow to start...", end='\r')
            
            time.sleep(poll_interval)
        
        print(f"\n    ✗ Timeout after {int(time.time() - start_time)}s waiting for workflow")
        return None
    
    def download_workflow_artifacts(
        self, 
        run_id: int, 
        artifact_name: str,
        download_dir: Path
    ) -> Optional[Path]:
        """
        Download artifacts from a workflow run
        
        Args:
            run_id: Workflow run ID
            artifact_name: Name of artifact to download (partial match)
            download_dir: Directory to save artifacts
            
        Returns:
            Path to extracted artifact directory
        """
        # List artifacts for the run
        artifacts_url = f'{self.base_url}/actions/runs/{run_id}/artifacts'
        response = requests.get(artifacts_url, headers=self.headers)
        
        if response.status_code != 200:
            print(f"    ✗ Failed to list artifacts: {response.status_code}")
            return None
        
        artifacts = response.json()['artifacts']
        
        # Find matching artifact
        target_artifact = None
        for artifact in artifacts:
            if artifact_name.lower() in artifact['name'].lower():
                target_artifact = artifact
                break
        
        if not target_artifact:
            print(f"    ✗ Artifact '{artifact_name}' not found")
            return None
        
        # Download the artifact
        download_url = target_artifact['archive_download_url']
        response = requests.get(download_url, headers=self.headers)
        
        if response.status_code != 200:
            print(f"    ✗ Failed to download artifact: {response.status_code}")
            return None
        
        # Save and extract
        download_dir.mkdir(parents=True, exist_ok=True)
        zip_path = download_dir / f"{target_artifact['name']}.zip"
        
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        # Extract
        extract_dir = download_dir / target_artifact['name']
        extract_dir.mkdir(exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Clean up zip
        zip_path.unlink()
        
        print(f"    ✓ Artifact downloaded to: {extract_dir}")
        return extract_dir
    
    def trigger_and_wait_for_sast(
        self,
        branch: str,
        download_dir: Path
    ) -> Optional[Path]:
        """
        Complete workflow: trigger SAST, wait, download results
        
        Args:
            branch: Branch to scan
            download_dir: Where to save results
            
        Returns:
            Path to SARIF file if successful
        """
        print(f"\n  🔍 Triggering SAST scan on branch '{branch}'...")
        
        # Trigger workflow
        if not self.trigger_workflow('SAST Security Scan', branch):
            return None
        
        # Wait a bit for the run to start
        time.sleep(5)
        
        # Wait for completion
        run = self.wait_for_workflow_completion(
            branch=branch,
            workflow_name='SAST Security Scan',
            timeout=600,
            poll_interval=15
        )
        
        if not run:
            return None
        
        if run['conclusion'] != 'success':
            print(f"    ⚠️  Workflow completed with status: {run['conclusion']}")
        
        # Download artifacts
        print(f"\n  📥 Downloading SARIF artifacts...")
        artifact_dir = self.download_workflow_artifacts(
            run_id=run['id'],
            artifact_name='sast-results',
            download_dir=download_dir
        )
        
        if not artifact_dir:
            return None
        
        # Find the SARIF file - now named after branch
        # First try branch-specific name
        branch_sarif = artifact_dir / f"{branch}.sarif"
        if branch_sarif.exists():
            print(f"    ✓ Found SARIF: {branch}.sarif")
            return branch_sarif
        
        # Fall back to any SARIF file (for backward compatibility)
        sarif_files = list(artifact_dir.glob('*.sarif'))
        if not sarif_files:
            print(f"    ✗ No SARIF files found in artifact")
            print(f"    Expected: {branch}.sarif or *.sarif")
            return None
        
        print(f"    ✓ Found SARIF: {sarif_files[0].name}")
        return sarif_files[0]
    
    def create_pull_request(self, branch: str, title: str, body: str, 
                           base: str = 'main') -> Optional[Dict]:
        """
        Create a pull request
        
        Args:
            branch: Source branch name
            title: PR title
            body: PR description (supports markdown)
            base: Target branch (default: main)
        
        Returns:
            PR data dict or None if failed
        """
        url = f'{self.base_url}/pulls'
        
        data = {
            'title': title,
            'body': body,
            'head': branch,
            'base': base
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=30)
            response.raise_for_status()
            pr_data = response.json()
            
            print(f"✓ Pull request created: #{pr_data['number']}")
            print(f"  URL: {pr_data['html_url']}")
            
            return pr_data
        
        except requests.exceptions.HTTPError as e:
            if response.status_code == 422:
                # PR might already exist
                print(f"⚠️  Pull request might already exist for branch '{branch}'")
                return None
            else:
                print(f"✗ Failed to create PR: {e}")
                print(f"  Response: {response.text}")
                return None
        
        except Exception as e:
            print(f"✗ Error creating PR: {e}")
            return None


def compare_sarif_findings(
    original_sarif: Path,
    new_sarif: Path,
    fixed_findings: List[Dict]
) -> Dict:
    """
    Compare SARIF files to check if findings were fixed and calculate alert deltas
    
    Args:
        original_sarif: Path to original SARIF file
        new_sarif: Path to new SARIF file after fixes
        fixed_findings: List of findings that were attempted to fix
        
    Returns:
        Dict with:
        - validation_results: Per-finding validation status (targeted findings only)
        - alert_counts: Overall SARIF alert statistics
        - new_vulnerabilities: List of newly introduced vulnerabilities
    """
    print(f"\n  📊 Comparing SARIF results...")
    
    # Load both SARIF files
    with open(original_sarif, 'r', encoding='utf-8') as f:
        original_data = json.load(f)
    
    with open(new_sarif, 'r', encoding='utf-8') as f:
        new_data = json.load(f)
    
    # Extract findings from original with full details
    original_findings = {}  # key -> full result data
    original_rule_file_counts = Counter()  # (rule_id, file_path) -> count
    for run in original_data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId', '')
            locations = result.get('locations', [])
            for loc in locations:
                physical_loc = loc.get('physicalLocation', {})
                file_path = physical_loc.get('artifactLocation', {}).get('uri', '')
                region = physical_loc.get('region', {})
                start_line = region.get('startLine', 0)
                
                # Create unique identifier
                finding_key = f"{rule_id}:{file_path}:{start_line}"
                original_findings[finding_key] = {
                    'rule_id': rule_id,
                    'file_path': file_path,
                    'line': start_line,
                    'severity': result.get('level', 'warning')
                }
                original_rule_file_counts[(rule_id, file_path)] += 1
    
    # Extract findings from new with full details
    new_findings = {}
    new_rule_file_counts = Counter()  # (rule_id, file_path) -> count
    for run in new_data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId', '')
            locations = result.get('locations', [])
            for loc in locations:
                physical_loc = loc.get('physicalLocation', {})
                file_path = physical_loc.get('artifactLocation', {}).get('uri', '')
                region = physical_loc.get('region', {})
                start_line = region.get('startLine', 0)
                
                finding_key = f"{rule_id}:{file_path}:{start_line}"
                new_findings[finding_key] = {
                    'rule_id': rule_id,
                    'file_path': file_path,
                    'line': start_line,
                    'severity': result.get('level', 'warning')
                }
                new_rule_file_counts[(rule_id, file_path)] += 1
    
    # Calculate overall alert counts
    original_total = len(original_findings)
    new_total = len(new_findings)
    
    # Identify newly introduced vulnerabilities by rule+file count increase
    new_vulnerabilities = []
    for (rule_id, file_path), new_count in new_rule_file_counts.items():
        original_count = original_rule_file_counts.get((rule_id, file_path), 0)
        increase = new_count - original_count
        if increase > 0:
            severity = 'warning'
            for finding in new_findings.values():
                if finding['rule_id'] == rule_id and finding['file_path'] == file_path:
                    severity = finding.get('severity', 'warning')
                    break
            new_vulnerabilities.append({
                'rule_id': rule_id,
                'file_path': file_path,
                'count_increase': increase,
                'severity': severity
            })
    
    # Check each targeted finding using rule+file count reduction budget
    validation_results = {}
    targeted_fixed = 0
    targeted_still_present = 0
    
    reduction_budget = {}
    for key, original_count in original_rule_file_counts.items():
        new_count = new_rule_file_counts.get(key, 0)
        reduction_budget[key] = max(0, original_count - new_count)
    
    for finding in fixed_findings:
        finding_id = finding['finding_id']
        
        # Skip DAST-only findings
        if not finding.get('sast', {}).get('present'):
            validation_results[finding_id] = {
                'validated': False,
                'reason': 'DAST-only finding, skipped SAST validation'
            }
            continue
        
        # Build the rule+file key for this finding
        sast = finding['sast']
        rule_id = sast.get('rule_id', '')
        file_path = sast.get('location', {}).get('file_path', '')
        rule_file_key = (rule_id, file_path)
        
        original_count = original_rule_file_counts.get(rule_file_key, 0)
        remaining_reduction = reduction_budget.get(rule_file_key, 0)
        
        if original_count == 0:
            validation_results[finding_id] = {
                'validated': None,
                'reason': 'Finding rule/file pair not found in original SARIF'
            }
        elif remaining_reduction > 0:
            validation_results[finding_id] = {
                'validated': True,
                'reason': f'Rule count reduced for {rule_id} in {file_path}'
            }
            targeted_fixed += 1
            reduction_budget[rule_file_key] = remaining_reduction - 1
        else:
            validation_results[finding_id] = {
                'validated': False,
                'reason': f'Rule still present for {rule_id} in {file_path}'
            }
            targeted_still_present += 1
    
    # Return comprehensive results
    return {
        'validation_results': validation_results,
        'alert_counts': {
            'original_total': original_total,
            'new_total': new_total,
            'targeted_count': len([f for f in fixed_findings if f.get('sast', {}).get('present')]),
            'targeted_fixed': targeted_fixed,
            'targeted_still_present': targeted_still_present,
            'new_introduced': len(new_vulnerabilities),
            'net_reduction': original_total - new_total
        },
        'new_vulnerabilities': new_vulnerabilities
    }
