"""Resume an interrupted A cell with identical protocol and recorded history."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.project_paths import synthetic_repo
parser = argparse.ArgumentParser()
parser.add_argument('--model', choices=['gemma-4-31b-it', 'qwen2.5-coder-1.5b-instruct-q4km'], required=True)
args = parser.parse_args()
out = ROOT / 'review_results' / f'{args.model}-A-synthetic-fivefree-v2-r1'
env = dict(os.environ, AVR_INPUT_BUDGET_PER_MINUTE='12000', AVR_REQUEST_TIMEOUT='60', AVR_TRANSPORT_RETRIES='2')
for cycle in range(20):
    state = json.loads((out / 'manifest.json').read_text())
    if state['status'] == 'complete':
        print('Completed resumed comparison cell:', out.name, flush=True)
        break
    if state['status'] != 'interrupted_api_error':
        raise RuntimeError('Do not take over a running or differently failed cell')
    results = json.loads((out / 'results.json').read_text())
    last_error = json.dumps(results[-1]) if results else ''
    if any(reason in last_error for reason in ('SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST')):
        raise RuntimeError('Provider content refusal; no automatic retry')
    cli = [sys.executable, str(ROOT / 'review/runner.py'), 'run', '--repo', str(synthetic_repo()),
           '--sarif', str(ROOT / 'review_results/baseline-synthetic/scan.sarif'), '--out', str(out),
           '--model', args.model, '--condition', 'A', '--context-profile', 'compact', '--rescan', '--resume',
           '--provider', 'local' if args.model.startswith('qwen') else 'gemini']
    with (out / 'supervisor-recovery.log').open('a', encoding='utf-8') as log:
        log.write(f'\nAdditional recovery cycle {cycle+1}\n'); log.flush()
        subprocess.run(cli, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    state = json.loads((out / 'manifest.json').read_text())
    print(args.model, state['status'], state.get('processed_findings'), flush=True)
    if state['status'] == 'complete':
        break
    if cycle < 19:
        time.sleep(30)
