"""
Test the evaluation system with existing data
"""
import sys
from pathlib import Path
from evaluation import PipelineEvaluator

def main():
    """Test evaluation with most recent branch"""
    # Find most recent branch report
    reports_dir = Path(__file__).parent / "../reports"
    
    if not reports_dir.exists():
        print("No reports directory found. Run the pipeline first.")
        return
    
    # Get all branch directories
    branches = [d for d in reports_dir.iterdir() if d.is_dir()]
    
    if not branches:
        print("No branch reports found. Run the pipeline first.")
        return
    
    # Sort by modification time (most recent first)
    branches.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    latest_branch = branches[0]
    
    print(f"\n{'='*70}")
    print(f"Testing Evaluation System")
    print(f"{'='*70}")
    print(f"\nUsing branch: {latest_branch.name}")
    
    # Check if metrics exist
    metrics_file = latest_branch / "metrics.json"
    summaries_file = latest_branch / "summaries.json"
    
    print(f"\n📊 Data availability:")
    print(f"  ✓ Metrics: {metrics_file.exists()}")
    print(f"  ✓ Summaries: {summaries_file.exists()}")
    print(f"  ✓ Coverage: {(latest_branch / 'coverage_after_fixes.json').exists()}")
    
    # Create evaluator
    try:
        evaluator = PipelineEvaluator(reports_dir, latest_branch.name)
        
        # Test individual metric calculations
        print(f"\n{'='*70}")
        print("Testing Individual Metrics")
        print(f"{'='*70}")
        
        print("\n1. Vulnerability Fix Rate:")
        fix_rate = evaluator.calculate_fix_rate()
        for key, value in fix_rate.items():
            print(f"   {key}: {value}")
        
        print("\n2. Token Usage:")
        tokens = evaluator.calculate_token_usage()
        for key, value in tokens.items():
            print(f"   {key}: {value}")
        
        print("\n3. Efficiency Score:")
        efficiency = evaluator.calculate_efficiency_score(fix_rate, tokens)
        for key, value in efficiency.items():
            print(f"   {key}: {value}")
        
        print("\n4. Code Minimality:")
        minimality = evaluator.calculate_code_minimality()
        for key, value in minimality.items():
            if key != 'files_modified':
                print(f"   {key}: {value}")
        
        print("\n5. Coverage Change:")
        coverage = evaluator.calculate_coverage_change()
        for key, value in coverage.items():
            print(f"   {key}: {value}")
        
        print("\n6. Fix Duration:")
        duration = evaluator.calculate_fix_duration()
        for key, value in duration.items():
            print(f"   {key}: {value}")
        
        # Test full evaluation (without SARIF comparison for now)
        print(f"\n{'='*70}")
        print("Generating Full Evaluation Report")
        print(f"{'='*70}")
        
        evaluation = evaluator.generate_evaluation(sarif_comparison=None)
        
        # Print summary
        evaluator.print_summary(evaluation)
        
        # Save evaluation
        eval_file = evaluator.save_evaluation()
        print(f"\n✓ Evaluation saved to: {eval_file}")
        
    except Exception as e:
        print(f"\n❌ Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
