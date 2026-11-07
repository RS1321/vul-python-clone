"""Run ordinary application checks on completed external-application runs."""
import argparse
import json
from pathlib import Path
import re
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def cycle():
    env = {k: v for k, v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    rows = []
    for dataset in ('pygoat', 'vampi'):
        python = ROOT / f'.review-work/{dataset}-env/Scripts/python.exe'
        if not python.exists():
            continue
        paths = sorted((ROOT / 'review_results').glob(f'*-{dataset}-fivefree-v2-r1/manifest.json'))
        for manifest in paths:
            state = json.loads(manifest.read_text(encoding='utf-8'))
            if state.get('status') != 'complete':
                continue
            out = ROOT / 'continuation/runtime-post' / manifest.parent.name
            record = out / 'runtime.json'
            if not out.exists():
                proc = subprocess.run([str(python), str(ROOT / f'review/{dataset}_runtime.py'),
                    '--repo', str(manifest.parent / 'source'), '--out', str(out)],
                    capture_output=True, text=True, timeout=180, env=env)
                out.mkdir(parents=True, exist_ok=True)
                (out / 'runner.log').write_text(proc.stdout + proc.stderr, encoding='utf-8')
                if not record.exists():
                    record.write_text(json.dumps({'passed': False, 'infrastructure_error': True, 'returncode': proc.returncode}), encoding='utf-8')
            rows.append({'run': manifest.parent.name, 'dataset': dataset,
                         'runtime': json.loads(record.read_text(encoding='utf-8'))})
    path = ROOT / 'continuation/results/external-runtime-summary.json'
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(rows, indent=2), encoding='utf-8')
    temporary.replace(path)
    return len(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--watch', action='store_true')
    args = parser.parse_args()
    while True:
        print('Completed external application runtime checks:', cycle(), flush=True)
        if not args.watch:
            break
        time.sleep(30)
