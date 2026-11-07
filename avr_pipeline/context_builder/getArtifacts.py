"""Download and extract GitHub Actions artifacts."""

import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

import requests
from dotenv import load_dotenv


def get_latest_artifacts(github_token: str, repo: str, branch: str = "main") -> dict:
    """
    Get the latest workflow run artifacts from a specific branch.

    Args:
        github_token: GitHub personal access token
        repo: Repository in format "owner/repo"
        branch: Branch name to filter by (default: "main")

    Returns:
        Dict with artifact types ("sast", "dast") mapped to artifact IDs
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        # Get the latest workflow runs from specific branch
        url = f"https://api.github.com/repos/{repo}/actions/runs"
        params = {"status": "completed", "branch": branch, "per_page": 20}
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        runs = response.json().get("workflow_runs", [])
        if not runs:
            print(f"✗ No completed workflow runs found on branch '{branch}'")
            return {}

        # Look for latest SAST and DAST artifacts
        sast_artifact = None
        dast_artifact = None
        
        for run in runs:
            run_id = run["id"]
            run_branch = run.get("head_branch", "")
            
            # Skip if not the target branch
            if run_branch != branch:
                continue
            
            # Get artifacts for this run
            artifacts_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
            artifacts_response = requests.get(artifacts_url, headers=headers, timeout=30)
            artifacts_response.raise_for_status()

            artifacts_data = artifacts_response.json().get("artifacts", [])
            
            for artifact in artifacts_data:
                artifact_name = artifact["name"]
                artifact_id = artifact["id"]
                
                # Find latest SAST artifact (pattern: starts with "sast-")
                if not sast_artifact and artifact_name.startswith("sast-"):
                    sast_artifact = {"name": artifact_name, "id": artifact_id}
                    print(f"✓ Found latest SAST: '{artifact_name}' from {branch} branch")
                
                # Find latest DAST artifact (pattern: starts with "dast-")
                if not dast_artifact and artifact_name.startswith("dast-"):
                    dast_artifact = {"name": artifact_name, "id": artifact_id}
                    print(f"✓ Found latest DAST: '{artifact_name}' from {branch} branch")
                
                # Stop if we found both
                if sast_artifact and dast_artifact:
                    break
            
            # Stop searching runs if we found both
            if sast_artifact and dast_artifact:
                break

        if not sast_artifact and not dast_artifact:
            print(f"✗ No SAST or DAST artifacts found on branch '{branch}'")
            return {}
        
        result = {}
        if sast_artifact:
            result["sast"] = sast_artifact["id"]
        if dast_artifact:
            result["dast"] = dast_artifact["id"]
        
        return result

    except requests.HTTPError as e:
        print(f"✗ HTTP error: {e}")
        return {}
    except Exception as e:
        print(f"✗ Error fetching artifacts: {e}")
        return {}


def download_artifact(artifact_id: str, github_token: str, output_path: str) -> bool:
    """
    Download artifact from GitHub Actions.

    Args:
        artifact_id: GitHub artifact ID
        github_token: GitHub personal access token
        output_path: Path to save the artifact

    Returns:
        True if successful, False otherwise
    """
    url = f"https://api.github.com/repos/Deep-Jiwan/vul-python-app/actions/artifacts/{artifact_id}/zip"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()

        # Save to file
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        return True

    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"✗ Artifact {artifact_id} not found or expired")
        elif e.response.status_code == 401:
            print("✗ Authentication failed. Check your GitHub token")
        else:
            print(f"✗ HTTP error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error downloading artifact: {e}")
        return False


def extract_artifact(zip_path: str, target_dir: str, target_file: str) -> bool:
    """
    Extract specific file from ZIP archive.

    Args:
        zip_path: Path to ZIP file
        target_dir: Directory to extract to
        target_file: Specific file to extract (or None for all)

    Returns:
        True if successful, False otherwise
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            file_list = zip_ref.namelist()

            if target_file:
                # Extract specific file
                if target_file in file_list:
                    zip_ref.extract(target_file, target_dir)
                    print(f"✓ Extracted {target_file} to {target_dir}")
                    return True
                else:
                    # Try to find file by partial match
                    matching_files = [f for f in file_list if target_file in f]
                    if matching_files:
                        for matched_file in matching_files:
                            zip_ref.extract(matched_file, target_dir)
                            # Rename if needed
                            extracted_path = Path(target_dir) / matched_file
                            final_path = Path(target_dir) / target_file
                            if extracted_path != final_path:
                                extracted_path.rename(final_path)
                            print(f"✓ Extracted {matched_file} as {target_file}")
                        return True
                    else:
                        print(f"✗ File {target_file} not found in archive")
                        return False
            else:
                # Extract all files
                zip_ref.extractall(target_dir)
                print(f"✓ Extracted all files to {target_dir}")
                return True

    except zipfile.BadZipFile:
        print(f"✗ Invalid ZIP file: {zip_path}")
        return False
    except Exception as e:
        print(f"✗ Error extracting archive: {e}")
        return False


def main():
    """Main entry point for artifact downloader."""
    parser = argparse.ArgumentParser(
        description="Download GitHub Actions artifacts for security scans"
    )
    parser.add_argument(
        "--repo",
        default="Deep-Jiwan/vul-python-app",
        help="GitHub repository (default: Deep-Jiwan/vul-python-app)",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to fetch artifacts from (default: main)",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Directory to save artifacts (default: artifacts)",
    )
    parser.add_argument(
        "--token",
        help="GitHub token (overrides .env)",
    )

    args = parser.parse_args()

    # Load environment variables
    load_dotenv()

    # Get GitHub token
    github_token = args.token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("✗ Error: GITHUB_TOKEN not found in .env or --token argument")
        print("  Get a token at: https://github.com/settings/tokens")
        sys.exit(1)

    # Ensure artifacts directory exists
    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Create temp directory for downloads
    temp_dir = artifacts_dir / "temp"
    temp_dir.mkdir(exist_ok=True)

    # Get latest artifacts from specified branch
    print(f"🔍 Searching for latest artifacts on '{args.branch}' branch...")
    artifact_map = get_latest_artifacts(github_token, args.repo, args.branch)
    
    if not artifact_map:
        print("✗ No artifacts found")
        sys.exit(1)

    success_count = 0
    sast_zip = temp_dir / "sast.zip"
    dast_zip = temp_dir / "dast.zip"

    # Download and extract SAST artifact
    sast_artifact_id = artifact_map.get("sast")
    if sast_artifact_id:
        print(f"\n📥 Downloading SAST artifact...")
        if download_artifact(str(sast_artifact_id), github_token, str(sast_zip)):
            if extract_artifact(
                str(sast_zip), str(artifacts_dir), "python-results.sarif"
            ):
                success_count += 1
    else:
        print(f"⚠️  No SAST artifact found on '{args.branch}' branch")

    # Download and extract DAST artifact
    dast_artifact_id = artifact_map.get("dast")
    if dast_artifact_id:
        print(f"\n📥 Downloading DAST artifact...")
        if download_artifact(str(dast_artifact_id), github_token, str(dast_zip)):
            if extract_artifact(str(dast_zip), str(artifacts_dir), "full-scan-report.json"):
                success_count += 1
    else:
        print(f"⚠️  No DAST artifact found on '{args.branch}' branch")

    # Cleanup temp files
    try:
        if sast_zip.exists():
            sast_zip.unlink()
        if dast_zip.exists():
            dast_zip.unlink()
        temp_dir.rmdir()
    except Exception:
        pass

    print()
    if success_count == 2:
        print("✅ All artifacts downloaded successfully")
    elif success_count > 0:
        print(f"⚠️  {success_count}/2 artifacts downloaded")
    else:
        print("❌ No artifacts downloaded")
        sys.exit(1)


if __name__ == "__main__":
    main()
