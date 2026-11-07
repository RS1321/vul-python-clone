"""Build script to generate context.json from security scan artifacts."""

import json
import argparse
from pathlib import Path

from parsers.code_fetcher import CodeFetcher
from parsers.codeql_parser import CodeQLParser
from parsers.zap_parser import ZAPParser
from parsers.context_generator import ContextGenerator
from parsers.filter_context import ContextFilter
from reorder_findings import FindingReorderer


def load_config(config_path: str = "config.json") -> dict:
    """Load configuration from JSON file."""
    script_dir = Path(__file__).parent
    config_file = script_dir / config_path
    
    with open(config_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    """Main entry point for context builder."""
    parser = argparse.ArgumentParser(
        description="Generate context.json from SAST and DAST scan artifacts"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    parser.add_argument(
        "--output",
        help="Override output path for context.json"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    print("Loading configuration...")
    config = load_config(args.config)
    
    # Resolve paths
    script_dir = Path(__file__).parent
    repo_path = script_dir / config["repo"]["path"]
    sast_file = script_dir / config["artifacts"]["sast_file"]
    dast_file = script_dir / config["artifacts"]["dast_file"]
    
    # Save outputs to artifacts folder
    artifacts_dir = sast_file.parent
    output_file = args.output or str(artifacts_dir / config["output"]["context_file"])
    
    # Validate paths
    if not repo_path.exists():
        print(f"✗ Error: Repository not found at {repo_path}")
        print("  Run: uv run python context_builder/cloneRepo.py")
        return
    
    if not sast_file.exists():
        print(f"✗ Error: SAST artifact not found at {sast_file}")
        print("  Run: uv run python context_builder/getArtifacts.py")
        return
    
    if not dast_file.exists():
        print(f"✗ Error: DAST artifact not found at {dast_file}")
        print("  Run: uv run python context_builder/getArtifacts.py")
        return
    
    print(f"✓ Repository: {repo_path}")
    print(f"✓ SAST file: {sast_file}")
    print(f"✓ DAST file: {dast_file}")
    print()
    
    # Initialize components
    print("Initializing parsers...")
    code_fetcher = CodeFetcher(str(repo_path))
    codeql_parser = CodeQLParser(code_fetcher, config["code_context"])
    zap_parser = ZAPParser()
    context_generator = ContextGenerator()
    
    # Parse SAST findings
    print("Parsing SAST findings...")
    sast_findings = codeql_parser.parse(str(sast_file))
    print(f"✓ Found {len(sast_findings)} SAST findings")
    
    # Parse DAST findings
    print("Parsing DAST findings...")
    dast_findings = zap_parser.parse(str(dast_file))
    print(f"✓ Found {len(dast_findings)} DAST findings")
    print()
    
    # Generate context
    print("Generating context...")
    context_generator.add_sast_findings(sast_findings)
    context_generator.add_dast_findings(dast_findings)
    context_generator.generate_context(output_file, config)
    
    print()
    print(f"✓ Context saved to: {output_file}")
    
    # Apply filtering based on config
    print()
    print("Applying filters...")
    filtering_config = config.get("filtering", {})
    sast_depth = filtering_config.get("sast_depth", "low")
    dast_depth = filtering_config.get("dast_depth", "low")
    
    print(f"  SAST depth: {sast_depth}")
    print(f"  DAST depth: {dast_depth}")
    
    # Load the generated context
    with open(output_file, 'r', encoding='utf-8') as f:
        context = json.load(f)
    
    # Apply filtering
    context_filter = ContextFilter(sast_depth=sast_depth, dast_depth=dast_depth)
    filtered_context = context_filter.filter_context(context)
    
    # Save filtered context to artifacts folder
    filtered_output = str(artifacts_dir / config["output"]["filtered_context_file"])
    with open(filtered_output, 'w', encoding='utf-8') as f:
        json.dump(filtered_context, f, indent=2)
    
    # Print statistics
    stats = filtered_context['filtering_applied']['statistics']
    print()
    print(f"✓ Filtered context saved to: {filtered_output}")
    print(f"  Total findings: {stats['total_input']} → {stats['total_input'] - stats['excluded']}")
    print(f"  - Correlated: {stats['included_correlated']}")
    print(f"  - SAST only: {stats['included_sast_only']}")
    print(f"  - DAST only: {stats['included_dast_only']}")
    print(f"  - Excluded: {stats['excluded']}")

    # Reorder findings by descending line number (highest line first) so that
    # sequential fixes don't shift line numbers for findings not yet processed.
    print()
    print("Reordering findings (descending line number)...")
    reorderer = FindingReorderer(filtered_output, backup=False)
    reorderer.load_context()
    reorderer.reorder_findings('descending_line')
    reorderer.save_context()
    print("✓ Findings ordered: highest line number first")


if __name__ == "__main__":
    main()
