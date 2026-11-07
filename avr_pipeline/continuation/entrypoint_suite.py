"""Apply the same startup contract to the baseline and completed synthetic cells."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.project_paths import synthetic_repo
from review.runner import dump

inputs = [('baseline', synthetic_repo())]
for path in sorted((ROOT / 'review_results').glob('*synthetic*/manifest.json')):
    state = json.loads(path.read_text())
    if state.get('status') == 'complete' and state.get('eligible_findings') == 29:
        inputs.append((path.parent.name, path.parent / 'source'))
rows = []
env = {k: v for k, v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
env.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
for name, repo in inputs:
    out = ROOT / 'continuation/runtime-startup' / name
    record = out / 'startup.json'
    if not record.exists():
        proc = subprocess.run([sys.executable, str(ROOT / 'review/entrypoint_check.py'), '--repo', str(repo), '--out', str(out)],
                              env=env, capture_output=True, text=True, encoding='utf-8', timeout=30)
        if not record.exists():
            out.mkdir(parents=True, exist_ok=True)
            dump(record, {'passed': False, 'infrastructure_error': proc.stderr[-1000:]})
    rows.append({'run': name, **json.loads(record.read_text())})
dump(ROOT / 'continuation/results/startup-summary.json', rows)
print(json.dumps({'checked': len(rows), 'passed': sum(r['passed'] for r in rows)}))
