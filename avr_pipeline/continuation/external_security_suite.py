"""Measure all completed external candidates with the same local oracles."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'continuation/results/completion/external-v3'


def main():
    jobs = []
    for dataset in ('pygoat', 'vampi'):
        states = [('baseline', ROOT / 'benchmarks' / dataset)]
        for path in sorted((ROOT / 'review_results').glob(f'*-{dataset}-fivefree-v2-r1/manifest.json')):
            if json.loads(path.read_text())['status'] == 'complete':
                states.append((path.parent.name, path.parent / 'source'))
        kinds = ['pygoat', 'lab-xss_lab', 'lab-sql_injection_lab', 'lab-ssrf_lab', 'lab-command_injection_lab'] if dataset == 'pygoat' else ['vampi']
        for state, source in states:
            for kind in kinds:
                jobs.append((dataset, state, source, kind))
    env = {k: v for k, v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}

    def worker(job):
        dataset, state, source, kind = job
        out = OUT / dataset / state / kind
        record = out / 'security.json'
        if not record.exists():
            if out.exists():
                raise ValueError('Incomplete prior output; use a fresh suite version: ' + str(out))
            runtime = 'vampi' if kind.startswith('lab-') else dataset
            python = ROOT / f'.review-work/{runtime}-env/Scripts/python.exe'
            p = subprocess.run([str(python), str(ROOT / 'review/external_security.py'), '--kind', kind,
                                '--repo', str(source), '--out', str(out)], env=env, capture_output=True, text=True, timeout=180)
            out.mkdir(parents=True, exist_ok=True)
            (out / 'runner.log').write_text(p.stdout + p.stderr, encoding='utf-8')
        row = {'dataset': dataset, 'state': state, 'kind': kind}
        row['result'] = json.loads(record.read_text()) if record.exists() else {'infrastructure_error': True}
        print(dataset, state, kind, row['result'].get('security_passed'), row['result'].get('security_total'), flush=True)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(worker, jobs))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'summary.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
