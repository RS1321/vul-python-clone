"""Run matched free-cohort tool-agent repetitions with serialized scanner use."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review import agent_baseline
from review.controlled_worker import scanner_lock
from review.runner import dump


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=['vampi','flask-webgoat','synthetic','pygoat'], default='flask-webgoat')
    parser.add_argument('--model', default='gemma-4-26b-a4b-it')
    parser.add_argument('--provider', choices=['gemini','local'], default='gemini')
    args = parser.parse_args()
    cohort = json.loads((ROOT/'review/validated-cohort.json').read_text())
    if dict(model=args.model, provider=args.provider) not in cohort:
        parser.error('Use a declared free/local cohort model')
    original_scan = agent_baseline.scan

    def serialized_scan(*scan_args, **scan_kwargs):
        with scanner_lock(ROOT/'.review-work/controlled-scanner.lock'):
            return original_scan(*scan_args, **scan_kwargs)

    agent_baseline.scan = serialized_scan
    for repetition in (1,2,3):
        out = ROOT/f'review_results/{args.model}-tool-agent-{args.dataset}-review2-validated-r{repetition}'
        if out.exists():
            manifest = out/'manifest.json'
            if manifest.exists() and json.loads(manifest.read_text()).get('status') == 'complete':
                print('Already complete: '+out.name, flush=True)
                continue
            raise ValueError('An incomplete agent run is retained; choose an explicit new attempt instead of overwriting it')
        run_args = SimpleNamespace(repo=str(ROOT/'benchmarks'/args.dataset),
                sarif=str(ROOT/f'review_results/baseline-{args.dataset}/scan.sarif'),out=str(out),
                model=args.model,provider=args.provider,max_tokens=8192,max_turns=None,
                repetition=repetition,codeql=None,pytest_args=[])
        print('Starting '+out.name, flush=True)
        agent_baseline.run(run_args)
        dump(out/'orchestration.json', {'sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'scheduling':'Same pinned inputs, 3*N tool turns, reply cap 8192; scanner lock affects scheduling only'})
        status = json.loads((out/'manifest.json').read_text())['status']
        if status != 'complete':
            raise SystemExit('Agent run did not complete: '+status)


if __name__ == '__main__':
    main()
