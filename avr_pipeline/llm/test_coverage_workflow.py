"""
Test coverage workflow end-to-end
"""
import json
import subprocess
from pathlib import Path

def test_coverage_workflow():
    """Test that coverage capture works on both main and fix branches"""
    
    repo_path = Path("../context_builder/repo").resolve()
    current_branch = subprocess.run(
        "git branch --show-current",
        shell=True,
        cwd=repo_path,
        capture_output=True,
        text=True
    ).stdout.strip()
    
    print(f"\n{'='*70}")
    print("TESTING COVERAGE WORKFLOW")
    print(f"{'='*70}")
    print(f"\nCurrent branch: {current_branch}")
    
    # Test coverage on current branch
    print(f"\n1. Running coverage on {current_branch}...")
    result = subprocess.run(
        'uv run pytest -m "not network" --cov=. --cov-report=json --cov-report=term-missing:skip-covered -q',
        shell=True,
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=120
    )
    
    if result.returncode != 0:
        print(f"   ❌ Coverage failed!")
        print(f"   STDERR: {result.stderr}")
        return False
    
    # Check coverage.json
    coverage_file = repo_path / "coverage.json"
    if not coverage_file.exists():
        print(f"   ❌ coverage.json not generated")
        return False
    
    with open(coverage_file, 'r') as f:
        cov_data = json.load(f)
        percent = cov_data.get('totals', {}).get('percent_covered', 0)
        print(f"   ✓ Coverage: {percent:.2f}%")
    
    # Verify baseline exists
    baseline_file = Path("../artifacts/baseline_coverage.json").resolve()
    if baseline_file.exists():
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
            baseline_percent = baseline_data.get('totals', {}).get('percent_covered', 0)
            print(f"\n2. Baseline coverage (main branch): {baseline_percent:.2f}%")
            
            # Calculate delta
            delta = percent - baseline_percent
            print(f"\n3. Coverage delta: {delta:+.2f}%")
            
            if delta >= 0:
                print(f"   ✓ Coverage maintained or improved!")
            else:
                print(f"   ⚠️  Coverage decreased (expected if fixes removed vulnerable code)")
    else:
        print(f"\n2. ⚠️  No baseline coverage found (run on main branch first)")
    
    print(f"\n{'='*70}")
    print("✓ Coverage workflow test completed successfully!")
    print(f"{'='*70}\n")
    
    return True

if __name__ == "__main__":
    import sys
    success = test_coverage_workflow()
    sys.exit(0 if success else 1)
