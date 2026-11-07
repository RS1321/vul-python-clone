"""
Context Filtering Script
Filters context.json based on SAST/DAST severity depth settings
"""

import json
import argparse
from typing import Dict, List
from pathlib import Path

# Severity mappings (match what's in context.json after parsing)
SAST_SEVERITY_MAP = {
    "high": ["high", "critical"],
    "medium": ["high", "critical", "medium"],
    "low": ["high", "critical", "medium", "low"]
}

DAST_SEVERITY_MAP = {
    "high": ["high"],
    "medium": ["high", "medium"],
    "low": ["high", "medium", "low"]
}


class ContextFilter:
    """Filter context.json based on severity depth settings"""
    
    def __init__(
        self,
        sast_depth: str = "low",
        dast_depth: str = "low"
    ):
        """
        Initialize filter
        
        Args:
            sast_depth: "high", "medium", or "low"
            dast_depth: "high", "medium", or "low"
        """
        self.sast_depth = sast_depth.lower()
        self.dast_depth = dast_depth.lower()
        
        # Validate depths
        if self.sast_depth not in SAST_SEVERITY_MAP:
            raise ValueError(f"Invalid SAST depth: {sast_depth}")
        if self.dast_depth not in DAST_SEVERITY_MAP:
            raise ValueError(f"Invalid DAST depth: {dast_depth}")
        
        self.sast_allowed = SAST_SEVERITY_MAP[self.sast_depth]
        self.dast_allowed = DAST_SEVERITY_MAP[self.dast_depth]
    
    def filter_context(self, context: Dict) -> Dict:
        """
        Filter context based on severity settings
        
        Args:
            context: Full context.json loaded as dict
            
        Returns:
            Filtered context with only relevant findings
        """
        filtered_findings = []
        stats = {
            "total_input": len(context['findings']),
            "included_correlated": 0,
            "included_sast_only": 0,
            "included_dast_only": 0,
            "included_both_tools": 0,
            "excluded": 0
        }
        
        for finding in context['findings']:
            result = self._should_include_finding(finding)
            
            if result['include']:
                filtered_findings.append(finding)
                
                # Update stats
                if result['reason'] == 'correlated':
                    stats['included_correlated'] += 1
                elif result['reason'] == 'sast_only':
                    stats['included_sast_only'] += 1
                elif result['reason'] == 'dast_only':
                    stats['included_dast_only'] += 1
                elif result['reason'] == 'both_tools':
                    stats['included_both_tools'] += 1
            else:
                stats['excluded'] += 1
        
        # Add finding numbers to filtered findings
        for idx, finding in enumerate(filtered_findings, start=1):
            finding['finding_number'] = f"FINDING {idx:03d}"
        
        # Create filtered context
        filtered_context = context.copy()
        filtered_context['findings'] = filtered_findings
        
        # Update scan summary
        filtered_context['scan_summary']['total_findings'] = len(filtered_findings)
        filtered_context['scan_summary']['sast_findings'] = sum(
            1 for f in filtered_findings if f['sast']['present']
        )
        filtered_context['scan_summary']['dast_findings'] = sum(
            1 for f in filtered_findings if f['dast']['present']
        )
        
        # Recalculate severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in filtered_findings:
            severity = finding.get('baseline_severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        filtered_context['scan_summary'].update(severity_counts)
        
        # Add filtering metadata
        filtered_context['filtering_applied'] = {
            "sast_detection_depth": self.sast_depth,
            "dast_detection_depth": self.dast_depth,
            "statistics": stats
        }
        
        return filtered_context
    
    def _should_include_finding(self, finding: Dict) -> Dict:
        """
        Determine if finding should be included
        
        Returns:
            {
                "include": bool,
                "reason": str
            }
        """
        # Priority 1: Always include correlated findings
        if finding.get('correlation_group') is not None:
            return {
                "include": True,
                "reason": "correlated"
            }
        
        # Priority 2: Check individual tools
        sast_meets_criteria = False
        dast_meets_criteria = False
        
        # Check SAST
        if finding['sast']['present']:
            sast_severity = finding['sast'].get('severity')
            if sast_severity and sast_severity in self.sast_allowed:
                sast_meets_criteria = True
        
        # Check DAST
        if finding['dast']['present']:
            dast_risk = finding['dast'].get('risk')
            # Ignore "Informational" findings
            if dast_risk and dast_risk != "Informational":
                if dast_risk in self.dast_allowed:
                    dast_meets_criteria = True
        
        # Determine inclusion
        if sast_meets_criteria and dast_meets_criteria:
            return {"include": True, "reason": "both_tools"}
        elif sast_meets_criteria:
            return {"include": True, "reason": "sast_only"}
        elif dast_meets_criteria:
            return {"include": True, "reason": "dast_only"}
        else:
            return {"include": False, "reason": "below_threshold"}
    
    def print_statistics(self, stats: Dict):
        """Print filtering statistics"""
        print("\n=== Filtering Statistics ===")
        print(f"Total input findings: {stats['total_input']}")
        print(f"Included (correlated): {stats['included_correlated']} - Both tools detected, matched by CWE")
        print(f"Included (SAST only): {stats['included_sast_only']} - Only SAST detected, meets severity threshold")
        print(f"Included (DAST only): {stats['included_dast_only']} - Only DAST detected, meets severity threshold")
        print(f"Included (both tools, not correlated): {stats['included_both_tools']} - Both detected but different CWEs")
        print(f"Excluded: {stats['excluded']} - Below severity threshold")
        total_included = (
            stats['included_correlated'] +
            stats['included_sast_only'] +
            stats['included_dast_only'] +
            stats['included_both_tools']
        )
        print(f"\nTotal filtered findings: {total_included}")
        print("===========================\n")


def load_config() -> Dict:
    """Load config.json from context_builder directory"""
    # Try to find config.json
    script_dir = Path(__file__).parent
    config_paths = [
        script_dir.parent / "config.json",  # context_builder/config.json
        script_dir / "config.json",  # parsers/config.json
        Path("config.json"),  # Current directory
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
    
    return {}


def main():
    """CLI entry point"""
    # Load config first to get defaults
    config = load_config()
    
    # Get defaults from config
    default_sast_depth = config.get('filtering', {}).get('sast_depth', 'low')
    default_dast_depth = config.get('filtering', {}).get('dast_depth', 'low')
    default_input = None
    default_output = None
    
    if config:
        # Construct default paths relative to config location
        script_dir = Path(__file__).parent.parent  # context_builder directory
        context_file = config.get('output', {}).get('context_file', 'context.json')
        filtered_file = config.get('output', {}).get('filtered_context_file', 'filtered_context.json')
        default_input = str(script_dir / context_file)
        default_output = str(script_dir / filtered_file)
    
    parser = argparse.ArgumentParser(
        description="Filter context.json based on severity depth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use config.json parameters (no arguments needed)
  python context_builder/parsers/filter_context.py

  # Override with custom parameters
  python context_builder/parsers/filter_context.py --input runs/demo/context.json --sast-depth high

  # Filter with high severity only (both tools)
  python context_builder/parsers/filter_context.py --input runs/demo/context.json --sast-depth high --dast-depth high --verbose
        """
    )
    parser.add_argument(
        "--input",
        default=default_input,
        help=f"Path to input context.json (default: from config.json or '{default_input}')"
    )
    parser.add_argument(
        "--output",
        default=default_output,
        help=f"Path to output filtered_context.json (default: from config.json or '{default_output}')"
    )
    parser.add_argument(
        "--sast-depth",
        choices=["high", "medium", "low"],
        default=default_sast_depth,
        help=f"SAST detection depth (default: {default_sast_depth})"
    )
    parser.add_argument(
        "--dast-depth",
        choices=["high", "medium", "low"],
        default=default_dast_depth,
        help=f"DAST detection depth (default: {default_dast_depth})"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed statistics"
    )
    
    args = parser.parse_args()
    
    # Validate input path
    if not args.input:
        print("❌ Error: No input file specified and config.json not found")
        print()
        print("Either:")
        print("  1. Create config.json with output.context_file path")
        print("  2. Provide --input argument")
        return
    
    # Check if input file exists
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Error: Input file not found: {args.input}")
        print()
        print("You need to generate context.json first using:")
        print("  uv run python context_builder/build.py")
        return
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        # Default: same directory as input, named filtered_context.json
        output_path = input_path.parent / "filtered_context.json"
    
    # Load input context
    print(f"Loading context from: {args.input}")
    with open(args.input, 'r') as f:
        context = json.load(f)
    
    # Create filter
    filter_obj = ContextFilter(
        sast_depth=args.sast_depth,
        dast_depth=args.dast_depth
    )
    
    # Filter context
    print(f"Filtering with SAST={args.sast_depth}, DAST={args.dast_depth}")
    filtered_context = filter_obj.filter_context(context)
    
    # Print statistics
    if args.verbose:
        stats = filtered_context['filtering_applied']['statistics']
        filter_obj.print_statistics(stats)
    
    # Save output
    print(f"Saving filtered context to: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(filtered_context, f, indent=2)
    
    print(f"✓ Filtering complete!")
    print(f"  Input findings: {context['scan_summary']['total_findings']}")
    print(f"  Output findings: {filtered_context['scan_summary']['total_findings']}")


if __name__ == "__main__":
    main()
