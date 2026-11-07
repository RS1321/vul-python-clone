"""
Extract unsolved findings from SARIF comparison and list them
"""
import json
import sys

def extract_unsolved_findings(sarif_comparison_path: str):
    """
    Extract finding IDs that were not validated (still present)
    
    Args:
        sarif_comparison_path: Path to sarif_comparison.json
        
    Returns:
        List of unsolved finding IDs
    """
    try:
        with open(sarif_comparison_path, 'r') as f:
            comparison = json.load(f)
        
        validation_results = comparison.get('validation_results', {})
        unsolved = [fid for fid, result in validation_results.items() 
                   if not result.get('validated', False)]
        
        return unsolved
    except Exception as e:
        print(f"Error loading SARIF comparison: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_unsolved.py <path_to_sarif_comparison.json>")
        sys.exit(1)
    
    sarif_path = sys.argv[1]
    unsolved = extract_unsolved_findings(sarif_path)
    
    print(f"\n📊 Found {len(unsolved)} unsolved findings:\n")
    for i, fid in enumerate(unsolved, 1):
        print(f"{i:2d}. {fid}")
    
    print(f"\n✅ Total: {len(unsolved)} findings")
    
    # Print as command-line argument format
    print(f"\n💡 To run pipeline on these findings:")
    print(f"   python -m llm.fix_pipeline --from-sarif-comparison {sarif_path}")
