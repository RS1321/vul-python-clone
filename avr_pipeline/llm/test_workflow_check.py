"""
Debug script to check workflow status
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv(Path(__file__).parent.parent / '.env')

from github_integration import GitHubIntegration

def main():
    """Check workflow status for a branch"""
    if len(sys.argv) < 2:
        print("Usage: python test_workflow_check.py <branch_name>")
        sys.exit(1)
    
    branch_name = sys.argv[1]
    
    print(f"Checking workflows for branch: {branch_name}")
    
    github_repo = os.getenv('GITHUB_REPO')
    if not github_repo:
        print("❌ GITHUB_REPO not found in environment")
        sys.exit(1)
    
    github = GitHubIntegration(github_repo)
    
    # Get workflow runs for this branch
    runs_url = f'{github.base_url}/actions/runs'
    params = {
        'branch': branch_name,
        'per_page': 10
    }
    
    import requests
    response = requests.get(runs_url, headers=github.headers, params=params)
    
    if response.status_code != 200:
        print(f"❌ Failed to get workflow runs: {response.status_code}")
        sys.exit(1)
    
    runs = response.json()['workflow_runs']
    
    print(f"\nFound {len(runs)} workflow runs:\n")
    
    for i, run in enumerate(runs, 1):
        print(f"{i}. Workflow: {run['name']}")
        print(f"   ID: {run['id']}")
        print(f"   Status: {run['status']}")
        print(f"   Conclusion: {run.get('conclusion', 'N/A')}")
        print(f"   Created: {run['created_at']}")
        print(f"   URL: {run['html_url']}")
        print()
    
    # Try to find SAST workflow
    print("Looking for 'SAST Security Scan' workflow...")
    for run in runs:
        if 'sast' in run['name'].lower():
            print(f"✓ Found: {run['name']} (Status: {run['status']}, Conclusion: {run.get('conclusion', 'N/A')})")

if __name__ == "__main__":
    main()
