"""Paired authenticated active SQL/XSS scans of local baseline/hardened copies."""
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

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'oracle_validation/security-resolution-v6/active-scans-final'
FLAGS=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0


def start(command,out,env):
    out.parent.mkdir(parents=True,exist_ok=True)
    log=out.with_suffix('.log').open('w',encoding='utf-8')
    child=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,creationflags=FLAGS)
    ready=out/'ready.json'
    for _ in range(60):
        if child.poll() is not None:log.close();raise RuntimeError('Target failed: '+str(out))
        if ready.exists():return child,log,json.loads(ready.read_text())
        time.sleep(1)
    child.terminate();child.wait(timeout=10);log.close();raise RuntimeError('Target timed out')


def main():
    env={k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential',k,re.I)}
    jar=next((ROOT/'.review-work/zap').rglob('zap-2.17.0.jar'))
    rows=[]
    for dataset in ['pygoat','vampi']:
        for state in ['baseline','hardened']:
            folder=OUT/dataset/state;status=folder/'status.json'
            if status.exists():rows.append(json.loads(status.read_text()));continue
            folder.mkdir(parents=True,exist_ok=True)
            repo=ROOT/'benchmarks'/dataset if state=='baseline' else ROOT/f'oracle_validation/security-resolution-v6/{dataset}/source'
            children=[]
            try:
                extra=[]
                if dataset=='pygoat':
                    host_state=folder/'host-state'
                    host,log,data=start([str(ROOT/'.review-work/pygoat-env/Scripts/python.exe'),str(ROOT/'review/serve_external_scan.py'),
                        '--dataset','pygoat','--repo',str(repo),'--out',str(host_state),'--port','18620'],host_state,env)
                    children.append((host,log));extra=['--auth-host','http://127.0.0.1:18620','--auth-ready',str(host_state/'ready.json')]
                port=18622 if dataset=='pygoat' else 18623;target='http://127.0.0.1:'+str(port);state_dir=folder/'target-state'
                child,log,data=start([str(ROOT/'.review-work/vampi-env/Scripts/python.exe'),str(ROOT/'review/serve_active_scan.py'),
                    '--dataset',dataset,'--repo',str(repo),'--out',str(state_dir),'--port',str(port)]+extra,state_dir,env)
                children.append((child,log))
                session=requests.Session();session.trust_env=False
                anonymous=session.get(target+data['verify'],allow_redirects=False,timeout=5)
                authenticated=session.get(target+data['verify'],headers=data['headers'],allow_redirects=False,timeout=5)
                if anonymous.status_code not in (302,401,403) or authenticated.status_code!=200:raise RuntimeError('Authentication preflight failed')
                entries=[]
                for seed in data['seeds']:
                    item={'url':target+seed['path'],'method':seed.get('method','GET'),'headers':['Content-Type: application/x-www-form-urlencoded'],'responseCode':200}
                    if 'body' in seed:item['data']=seed['body']
                    if dataset=='pygoat' and item['method']=='POST':
                        # Keep CSRF validation enabled. Reuse a real form token
                        # and its matching Flask session for this exact lesson.
                        form=session.get(target+seed['path'],headers=data['headers'],timeout=5)
                        token=re.search(r'name="csrf_token" value="([^"]+)"',form.text)
                        if token:
                            from urllib.parse import quote
                            item['data']+='&csrf_token='+quote(token.group(1),safe='')
                            prepared=session.prepare_request(requests.Request('POST',target+seed['path']))
                            if prepared.headers.get('Cookie'):item['headers'].append('Cookie: '+prepared.headers['Cookie'])
                    entries.append(item)
                plan={'env':{'contexts':[{'name':'authenticated-local','urls':[target],'includePaths':['^'+re.escape(target)+r'/.*$']}],
                    'parameters':{'failOnError':True,'failOnWarning':False,'progressToStdout':True}},'jobs':[
                    {'type':'requestor','requests':entries},
                    {'type':'activeScan','parameters':{'context':'authenticated-local','threadPerHost':2,'maxScanDurationInMins':3,'maxRuleDurationInMins':1,'injectPluginIdInHeader':True},
                     'policyDefinition':{'defaultThreshold':'Off','defaultStrength':'Low','rules':[{'id':40012,'threshold':'Medium','strength':'Low'},{'id':40018,'threshold':'Medium','strength':'Low'}]}},
                    {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
                    {'type':'report','parameters':{'template':'traditional-json','reportDir':str(folder),'reportFile':'scan.json','reportTitle':'Authenticated active SQL/XSS scan'}}]}
                private_plan=state_dir/'plan.yaml'
                private_plan.write_text(yaml.safe_dump(plan,sort_keys=False),encoding='utf-8')
                header,value=next(iter(data['headers'].items()))
                scan_env=dict(env,ZAP_AUTH_HEADER=header,ZAP_AUTH_HEADER_VALUE=value,ZAP_AUTH_HEADER_SITE='127.0.0.1')
                with (folder/'zap.log').open('w',encoding='utf-8') as stream:
                    proc=subprocess.run([shutil.which('java'),'-Xmx768m','-jar',str(jar),'-cmd','-dir',str(folder/'zap-home'),'-autorun',str(private_plan),'-config','connection.timeoutInSecs=5'],
                        cwd=state_dir,env=scan_env,stdout=stream,stderr=subprocess.STDOUT,timeout=360,creationflags=FLAGS)
                public_plan=private_plan.read_text()
                public_plan=re.sub(r'csrf_token=[A-Za-z0-9_.%-]+','csrf_token=<FIXTURE_TOKEN>',public_plan)
                public_plan=re.sub(r'Cookie: [^\r\n]+','Cookie: <FIXTURE_SESSION>',public_plan)
                (folder/'plan.yaml').write_text(public_plan,encoding='utf-8')
                traffic=json.loads((state_dir/'traffic.json').read_text())
                result=dict(dataset=dataset,state=state,returncode=proc.returncode,anonymous_status=anonymous.status_code,authenticated_status=authenticated.status_code,
                    traffic=traffic,profile='authenticated active SQL injection 40018 and reflected XSS 40012; local disposable data; 3 minute scan cap; no other active rules')
                result['status']='complete' if proc.returncode in (0,2) and (folder/'scan.json').exists() and sum(traffic['active_rules'].values())>0 else 'failed'
                status.write_text(json.dumps(result,indent=2),encoding='utf-8');rows.append(result)
                print(dataset,state,result['status'],traffic,flush=True)
            finally:
                for child,log in reversed(children):
                    child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    log.close()
    (OUT/'summary.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')


if __name__=='__main__':main()
