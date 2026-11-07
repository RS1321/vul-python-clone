"""Conditional A/B pilot for the small local model with a declared reply cap."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuation.sweep import worker
from review.runner import dump

# Let the prior stopped-service trial save its own clean checkpoints and finish.
prior = ROOT / 'continuation/results/qwen05-final.json'
deadline = time.monotonic() + 900
while not prior.exists() and time.monotonic() < deadline:
    time.sleep(5)
if not prior.exists():
    raise RuntimeError('Prior supervisor has not finished; no competing local run is started')
dump(ROOT / 'continuation/results/local-small-budget-amendment.json', {
    'model': 'qwen2.5-coder-0.5b-instruct-q4km', 'max_tokens': 1024,
    'scope': 'Within-model controlled A/B; both use the same 1024-token cap. Other models used 8192 tokens, so cross-model ranks are not equal-budget comparisons.',
    'reason': 'The initial 8192-token local trial repeatedly exceeded the 180-second request deadline while generating thousands of tokens. That trial remains recorded and is excluded from the completed-pair table.',
    'generation_limit_policy': 'Output-limit replies are retained as unsuccessful generation attempts, with usage, and are never passed to the patcher.'})
log = (ROOT / '.review-work/local-qwen05/launcher.log').open('w', encoding='utf-8')
launcher = subprocess.Popen([sys.executable, '-u', str(ROOT / 'continuation/start_local_model.py'), '--small', '--serve'],
    cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
import requests
session = requests.Session(); session.trust_env = False
for _ in range(90):
    if launcher.poll() is not None:
        raise RuntimeError('Local model launcher exited')
    try:
        if session.get('http://127.0.0.1:18081/health', timeout=1).status_code == 200:
            break
    except requests.RequestException:
        pass
    time.sleep(1)
else:
    raise RuntimeError('Local model did not become ready')
result = worker('qwen2.5-coder-0.5b-instruct-q4km', [('synthetic', 'A'), ('synthetic', 'B')],
                tag='fivefree-v3-1024', max_tokens=1024)
dump(ROOT / 'continuation/results/qwen05-bounded-final.json', result)
print('Completed bounded local-model pair', flush=True)
