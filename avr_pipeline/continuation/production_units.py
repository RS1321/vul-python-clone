"""Compare upstream ordinary unit tests on pinned baseline and pilot patches."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'continuation/results/production-upstream-tests-v2'
OUT.mkdir(parents=True, exist_ok=True)
clean_env = {k: v for k, v in os.environ.items() if not re.search(r'api.?key|token|secret|password|credential|access.?key', k, re.I)}
rows = []
for state, repo in [('baseline', ROOT / 'benchmarks/urllib3-cve'),
                    ('patched', ROOT / 'continuation/results/production-urllib3/source')]:
    folder = OUT / ('urllib3-' + state)
    folder.mkdir(exist_ok=True)
    env = dict(clean_env, PYTHONPATH=os.pathsep.join(map(str, [repo/'src', repo, ROOT/'review'])), PYTHONDONTWRITEBYTECODE='1')
    python = ROOT / '.review-work/production-env/Scripts/python.exe'
    args = [str(python), '-m', 'pytest', str(repo / 'test/test_retry.py'), '--noconftest',
            '--rootdir=' + str(repo), '-p', 'no:cacheprovider', '-p', 'urllib3_retry_fixtures', '-q', '--tb=short',
            '--basetemp=' + str(folder / 'tmp'), '--junitxml=' + str(folder / 'results.xml')]
    proc = subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True, timeout=120)
    (folder / 'output.txt').write_text(proc.stdout + proc.stderr, encoding='utf-8')
    cases = list(ET.parse(folder / 'results.xml').iter('testcase')) if (folder / 'results.xml').exists() else []
    failures = [{'name': c.attrib.get('name'), 'class': c.attrib.get('classname'),
                 'message': (c.find('failure') if c.find('failure') is not None else c.find('error')).attrib.get('message')}
                for c in cases if c.find('failure') is not None or c.find('error') is not None]
    rows.append({'dataset': 'urllib3', 'state': state, 'returncode': proc.returncode,
                 'scope': 'Upstream test_retry.py plus upstream timezone context and pytest-freezegun; unrelated server conftest disabled',
                 'tests': len(cases), 'failed': len(failures),
                 'skipped': sum(c.find('skipped') is not None for c in cases), 'failures': failures})
node = shutil.which('node')
if not node:
    raise RuntimeError('Node is required')
tape = ROOT / '.review-work/minimist-test-deps/node_modules/tape/bin/tape'
if not tape.exists():
    raise RuntimeError('Pinned Tape test dependency is required')
for state, repo in [('baseline', ROOT / 'benchmarks/minimist-cve'),
                    ('patched', ROOT / 'continuation/results/production-minimist-v2/source')]:
    # The prototype-pollution reproducer is outside this ordinary API test run.
    files = sorted(p for p in (repo / 'test').glob('*.js') if p.name != 'proto.js')
    env = dict(clean_env, NODE_PATH=str(tape.parents[2]))
    # Tape 3's asynchronous glob CLI can exit before every file is registered
    # on modern Node. Require the exact same selected files synchronously.
    loader = 'for (const file of JSON.parse(process.argv[1])) require(file);'
    proc = subprocess.run([node, '-e', loader, json.dumps(list(map(str, files)))], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=120)
    (OUT / ('minimist-' + state + '.tap')).write_text(proc.stdout + proc.stderr, encoding='utf-8')
    match = re.search(r'^# tests\s+(\d+)', proc.stdout, re.M)
    passed = re.search(r'^# pass\s+(\d+)', proc.stdout, re.M)
    rows.append({'dataset': 'minimist', 'state': state, 'returncode': proc.returncode,
                 'scope': 'Upstream ordinary parser tests; proto.js excluded; no security fix-rate claim',
                 'files': [p.name for p in files], 'tests': int(match[1]) if match else None,
                 'passed': int(passed[1]) if passed else None,
                 'failed': len(re.findall(r'^not ok\b', proc.stdout, re.M))})
(OUT / 'summary.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(json.dumps([{k: r.get(k) for k in ('dataset', 'state', 'tests', 'failed', 'returncode')} for r in rows]))
