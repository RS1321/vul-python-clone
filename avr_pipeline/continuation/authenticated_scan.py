"""Authenticated ZAP passive measurements on fixed read-only external routes.

Paired baseline/Gemini candidates. Security behavior is measured separately by
external_security_suite; passive alert disappearance is not exploit resolution.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'continuation/results/completion/authenticated-zap'


def main():
    rows = []
    env = {k: v for k, v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
    jar = next((ROOT / '.review-work/zap').rglob('zap-2.17.0.jar'))
    for dataset in ['pygoat', 'vampi']:
        for label in ['baseline', 'gemini-3.5-flash-lite']:
            out = OUT / dataset / label
            status = out / 'status.json'
            if status.exists():
                rows.append(json.loads(status.read_text()))
                continue
            out.mkdir(parents=True, exist_ok=True)
            repo = ROOT / 'benchmarks' / dataset if label == 'baseline' else ROOT / f'review_results/{label}-A-{dataset}-fivefree-v2-r1/source'
            port = 18620 if dataset == 'pygoat' else 18621
            target = 'http://127.0.0.1:' + str(port)
            state = out / 'target-state'
            log = (out / 'application.log').open('w', encoding='utf-8')
            child = subprocess.Popen([str(ROOT / f'.review-work/{dataset}-env/Scripts/python.exe'), str(ROOT / 'review/serve_external_scan.py'),
                '--dataset', dataset, '--repo', str(repo), '--out', str(state), '--port', str(port)], cwd=ROOT, env=env,
                stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
            try:
                ready = state / 'ready.json'
                for _ in range(60):
                    if child.poll() is not None:
                        raise RuntimeError('Target startup failed')
                    if ready.exists():
                        break
                    time.sleep(1)
                data = json.loads(ready.read_text())
                session = requests.Session()
                session.trust_env = False
                anonymous = session.get(target + data['verify'], allow_redirects=False, timeout=5)
                authenticated = session.get(target + data['verify'], headers=data['headers'], allow_redirects=False, timeout=5)
                if anonymous.status_code not in (302, 401, 403) or authenticated.status_code != 200:
                    raise RuntimeError('Authentication preflight did not discriminate')
                plan = {'env': {'contexts': [{'name':'fixed-authenticated-routes', 'urls':[target], 'includePaths':['^'+re.escape(target)+r'/.*$']}],
                        'parameters': {'failOnError':True, 'failOnWarning':False, 'progressToStdout':True}},
                        'jobs': [{'type':'requestor', 'requests':[{'url':target+path, 'method':'GET', 'headers':[k+': '+v for k,v in data['headers'].items()], 'responseCode':200} for path in data['paths']]},
                                 {'type':'passiveScan-wait', 'parameters':{'maxDuration':1}},
                                 {'type':'report', 'parameters':{'template':'traditional-json', 'reportDir':str(out), 'reportFile':'scan.json', 'reportTitle':'Authenticated fixed-route passive scan'}}]}
                private_plan = state / 'plan.yaml'
                private_plan.write_text(yaml.safe_dump(plan, sort_keys=False), encoding='utf-8')
                with (out / 'zap.log').open('w', encoding='utf-8') as zap_log:
                    proc = subprocess.run([shutil.which('java'), '-Xmx768m', '-jar', str(jar), '-cmd', '-dir', str(out/'zap-home'), '-autorun', str(private_plan),
                        '-config', 'connection.timeoutInSecs=5'], cwd=state, stdout=zap_log, stderr=subprocess.STDOUT, timeout=240, creationflags=flags, env=env)
                public_plan = private_plan.read_text()
                for value in data['headers'].values():
                    public_plan = public_plan.replace(value, '<EPHEMERAL_FIXTURE_AUTH>')
                (out / 'plan.yaml').write_text(public_plan, encoding='utf-8')
                result = dict(dataset=dataset, state=label, status='complete' if proc.returncode in (0,2) and (out/'scan.json').exists() else 'failed',
                    returncode=proc.returncode, anonymous_status=anonymous.status_code, authenticated_status=authenticated.status_code,
                    routes=data['paths'], authenticated=True, profile='fixed-route passive ZAP 2.17.0; no spider or active scan; no Docker labs',
                    implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
                status.write_text(json.dumps(result, indent=2), encoding='utf-8')
                rows.append(result)
                print(dataset, label, result['status'], flush=True)
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                log.close()
    (OUT / 'summary.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
