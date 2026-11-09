"""Execute installed Linux scanners and compare one pinned baseline, without LLMs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.project_paths import verify_input
from review.runner import checked, compare, dump, finding_counts, scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('/tmp/container-evidence'))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'running',
              'scope': 'Linux container installation and pinned baseline scanner check; no model experiment',
              'python': sys.version}
    try:
        report['zap'] = checked(['java', '-Xmx512m', '-jar', os.environ['ZAP_JAR'],
                                 '-cmd', '-version', '-dir', str(args.out/'zap-home')])
        checked([sys.executable, str(ROOT/'review/prepare_inputs.py'), '--datasets', 'flask-webgoat'])
        repo = ROOT/'benchmarks/flask-webgoat'
        baseline = ROOT/'review_results/baseline-flask-webgoat/scan.sarif'
        report['input'] = verify_input(repo, baseline, checked, 'flask-webgoat')
        measured = scan(repo, args.out/'flask-webgoat-sast')
        report['baseline_comparison'] = compare(finding_counts(repo, baseline), finding_counts(repo, measured))
        if report['baseline_comparison']['resolved_findings'] or report['baseline_comparison']['new_findings']:
            raise RuntimeError('Linux baseline differs from the recorded baseline; do not pool results')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        dump(args.out/'container-check.json', report)
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
