"""
Debug script to check workflow artifacts
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load environment
load_dotenv(Path(__file__).parent.parent / '.env')

from github_integration import GitHubIntegration

def main():
    """Check artifacts for a workflow run"""
    if len(sys.argv) < 2:
        print("Usage: python test_artifact_check.py <run_id>")
        sys.exit(1)
    
    run_id = sys.argv[1]
    
    print(f"Checking artifacts for workflow run: {run_id}")
    
    github_repo = os.getenv('GITHUB_REPO')
    if not github_repo:
        print("❌ GITHUB_REPO not found in environment")
        sys.exit(1)
    
    github = GitHubIntegration(github_repo)
    
    # Get artifacts for this run
    artifacts_url = f'{github.base_url}/actions/runs/{run_id}/artifacts'
    response = requests.get(artifacts_url, headers=github.headers)
    
    if response.status_code != 200:
        print(f"❌ Failed to get artifacts: {response.status_code}")
        sys.exit(1)
    
    artifacts = response.json()['artifacts']
    
    print(f"\nFound {len(artifacts)} artifacts:\n")
    
    for i, artifact in enumerate(artifacts, 1):
        print(f"{i}. Name: {artifact['name']}")
        print(f"   ID: {artifact['id']}")
        print(f"   Size: {artifact['size_in_bytes']} bytes")
        print(f"   Created: {artifact['created_at']}")
        print(f"   Expired: {artifact['expired']}")
        print()

if __name__ == "__main__":
    main()
