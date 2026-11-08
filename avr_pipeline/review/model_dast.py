"""Paired authenticated active SQL/XSS measurements of model-generated patches.

Runs only on loopback fixture copies, with identical fixed routes and scan policy.
The outer session gate is measurement containment, not native authorization repair.
"""
import argparse
from collections import Counter
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
sys.path.insert(0, str(ROOT))
from review.runner import digest, dump, checked


def measure(dataset, repo, out, port, jar):
    out.mkdir(parents=True)
    state = out/'target-state'
    env = {k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    log = (out/'application.log').open('w', encoding='utf-8')
    child = subprocess.Popen([sys.executable, str(ROOT/'review/serve_manuscript_scan.py'), '--dataset', dataset,
                              '--repo', str(repo), '--out', str(state), '--port', str(port)],
                             env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
    result = {'status':'failed', 'dataset':dataset, 'profile':'authenticated fixed-route active SQL/XSS',
              'native_authorization_claim':False, 'model_patch_only':True}
    try:
        for _ in range(60):
            if child.poll() is not None:
                raise RuntimeError('Target startup/login failed; see application.log')
            if (state/'ready.json').exists():
                break
            time.sleep(1)
        else:
            raise RuntimeError('Target startup timeout')
        data = json.loads((state/'ready.json').read_text())
        target = f'http://127.0.0.1:{port}'
        http = requests.Session()
        http.trust_env = False
        anon = http.get(target+data['verify'], timeout=5, allow_redirects=False)
        auth = http.get(target+data['verify'], headers=data['headers'], timeout=5, allow_redirects=False)
        if anon.status_code != 401 or auth.status_code != 200:
            raise RuntimeError('Session-gate preflight failed')
        policy = {'defaultThreshold':'Off', 'defaultStrength':'Low', 'rules':[
            {'id':40012, 'threshold':'Medium', 'strength':'Low'},
            {'id':40018, 'threshold':'Medium', 'strength':'Low'}]}
        plan = {'env':{'contexts':[{'name':'model-measurement','urls':[target], 'includePaths':['^'+re.escape(target)+r'/.*$']}],
                       'parameters':{'failOnError':True,'failOnWarning':False,'progressToStdout':True}},
                'jobs':[{'type':'requestor', 'requests':[dict(url=target+s['path'], method=s.get('method','GET'),
                     headers=['Content-Type: application/x-www-form-urlencoded'], data=s.get('body',''), responseCode=200) for s in data['seeds']]},
                    {'type':'activeScan','parameters':{'context':'model-measurement','threadPerHost':2,
                        'maxScanDurationInMins':3,'maxRuleDurationInMins':1,'injectPluginIdInHeader':True}, 'policyDefinition':policy},
                    {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
                    {'type':'report','parameters':{'template':'traditional-json','reportDir':str(out), 'reportFile':'scan.json',
                                                  'reportTitle':'Model-generated paired authenticated active scan'}}]}
        plan_path = out/'plan.yaml'
        plan_path.write_text(yaml.safe_dump(plan, sort_keys=False))
        scan_env = dict(env, ZAP_AUTH_HEADER='Cookie', ZAP_AUTH_HEADER_VALUE=data['headers']['Cookie'], ZAP_AUTH_HEADER_SITE='127.0.0.1')
        java = shutil.which('java')
        if not java:
            raise RuntimeError('Java unavailable')
        with (out/'zap.log').open('w', encoding='utf-8') as stream:
            proc = subprocess.run([java, '-Xmx768m', '-jar', str(jar), '-cmd', '-dir', str(out/'zap-home'),
                                   '-autorun', str(plan_path), '-config', 'connection.timeoutInSecs=5'],
                                  cwd=state, env=scan_env, stdout=stream, stderr=subprocess.STDOUT,
                                  timeout=360, creationflags=flags)
        traffic = json.loads((state/'traffic.json').read_text())
        authenticated_active = traffic.get('active_authenticated_rules', {})
        complete = proc.returncode in (0, 2) and (out/'scan.json').exists() and all(authenticated_active.get(str(r), 0)>0 for r in (40012, 40018))
        alerts = Counter()
        if (out/'scan.json').exists():
            report = json.loads((out/'scan.json').read_text(encoding='utf-8-sig'))
            for site in report.get('site', []):
                for alert in site.get('alerts', []):
                    alerts[str(alert['pluginid'])] += len(alert.get('instances', []))
        result.update(status='complete' if complete else 'incomplete_active_evidence', returncode=proc.returncode,
                      anonymous_status=anon.status_code, authenticated_status=auth.status_code, traffic=traffic,
                      alerts_by_plugin=dict(alerts), alert_types=len(alerts), alert_instances=sum(alerts.values()),
                      seeds=data['seeds'], policy=policy, zap_jar_sha256=digest(jar),
                      implementation_sha256={str(p.relative_to(ROOT)):digest(p) for p in [Path(__file__), ROOT/'review/serve_manuscript_scan.py']})
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()
        log.close()
        # This file contains ephemeral login credentials and is not an artifact.
        if (state/'ready.json').exists():
            (state/'ready.json').unlink()
        dump(out/'status.json', result)
    print(dataset, out.name, result['status'], flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', choices=('synthetic','flask-webgoat'), required=True)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    run, baseline, out = args.run.resolve(), args.baseline.resolve(), args.out.resolve()
    m = json.loads((run/'manifest.json').read_text())
    if m.get('status') != 'complete' or not m.get('provider') or not (run/'results.json').exists():
        p.error('A completed model run is required; oracle_validation is excluded')
    if 'oracle_validation' in run.parts or m.get('source_commit') != checked(['git','rev-parse','HEAD'], baseline):
        p.error('Model run and pinned baseline must match')
    if out.exists():
        p.error('Use a fresh output directory')
    tool_root = Path(os.getenv('AVR_TOOL_ROOT', str(ROOT)))
    jars = list((tool_root/'.review-work/zap').rglob('zap-2.17.0.jar'))
    if len(jars) != 1:
        p.error('Provision pinned ZAP 2.17.0 under AVR_TOOL_ROOT')
    before = measure(args.dataset, baseline, out/'baseline', 18710, jars[0])
    after = measure(args.dataset, run/'source', out/'model', 18711, jars[0])
    complete = before['status'] == after['status'] == 'complete'
    record = {'dataset':args.dataset, 'model_run':run.name, 'source_commit':m['source_commit'],
              'model_manifest_sha256':digest(run/'manifest.json'), 'status':'complete' if complete else 'incomplete',
              'baseline':before, 'model':after, 'new_alert_types': sorted(set(after.get('alerts_by_plugin', {}))-set(before.get('alerts_by_plugin', {}))) if complete else None,
              'scope':'Bounded authenticated active SQL/XSS profile, no full crawl, no command/file/network injection; outer session gate is not native authorization proof.'}
    dump(out/'paired-status.json', record)


if __name__ == '__main__':
    main()
