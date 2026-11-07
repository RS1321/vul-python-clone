"""Run a bounded ZAP automation plan against an isolated local Flask clone."""
import argparse
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--repo', required=True)
parser.add_argument('--out', required=True)
parser.add_argument('--port', type=int, default=3000)
args = parser.parse_args()
repo, out = Path(args.repo).resolve(), Path(args.out).resolve()
out.mkdir(parents=True, exist_ok=True)
runtime = out / 'target-state'
runtime.mkdir(exist_ok=False)
target = f'http://127.0.0.1:{args.port}'
plan = {'env': {'contexts': [{'name':'local-benchmark','urls':[target],
         'includePaths':['^' + re.escape(target) + r'(?:/.*)?$']}],
         'parameters':{'failOnError':True,'failOnWarning':False,'progressToStdout':True}},
        'jobs':[{'type':'spider','parameters':{'context':'local-benchmark','maxDuration':1}},
                {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
                {'type':'activeScan','parameters':{'context':'local-benchmark','maxScanDurationInMins':5,
                                                 'maxRuleDurationInMins':1}},
                {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
                {'type':'report','parameters':{'template':'traditional-json','reportDir':str(out),
                                               'reportFile':'scan.json','reportTitle':'Local Flask ZAP scan'}}]}
(out/'plan.yaml').write_text(yaml.safe_dump(plan, sort_keys=False), encoding='utf-8')
# Respect the app's source debug setting while suppressing only the reloader.
server_code = '''import ast,sys
sys.path.insert(0,sys.argv[1])
import vulnerable_app as module
from pathlib import Path
tree=ast.parse(Path(sys.argv[1],'vulnerable_app.py').read_text(encoding='utf-8'))
debug=False
for node in ast.walk(tree):
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run':
        for kw in node.keywords:
            if kw.arg=='debug' and isinstance(kw.value,ast.Constant): debug=bool(kw.value.value)
module.init_database()
module.app.run(host='127.0.0.1',port=int(sys.argv[2]),debug=debug,use_reloader=False)
'''
flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
with (out/'app.log').open('w', encoding='utf-8') as app_log:
    child_env = {k:v for k,v in os.environ.items()
                 if not re.search(r'(api.?key|token|secret|password|credential|access.?key)', k, re.I)}
    app = subprocess.Popen([sys.executable,'-c',server_code,str(repo),str(args.port)], cwd=runtime,
                           stdout=app_log,stderr=subprocess.STDOUT,creationflags=flags,env=child_env)
    try:
        ready = False
        for _ in range(30):
            if app.poll() is not None: raise RuntimeError('App startup failed; see app.log')
            try:
                with urllib.request.urlopen(target + '/health', timeout=1) as response:
                    ready = response.status == 200
                if ready: break
            except OSError: time.sleep(1)
        if not ready: raise RuntimeError('App health check failed')
        jars = list((ROOT/'.review-work/zap').rglob('zap-2.17.0.jar'))
        if not jars: raise RuntimeError('ZAP archive is not installed')
        # CodeQL's trimmed JRE lacks java.scripting, which ZAP needs.
        java = shutil.which('java')
        if not java: raise RuntimeError('A full Java 17+ runtime is required for ZAP')
        command = [str(java),'-Xmx1024m','-jar',str(jars[0]),'-cmd','-dir',str(out/'zap-home'),
                   '-autorun',str(out/'plan.yaml'),'-config','connection.timeoutInSecs=10']
        with (out/'zap.log').open('w',encoding='utf-8') as log:
            result = subprocess.run(command, cwd=runtime, stdout=log,stderr=subprocess.STDOUT,
                                    timeout=900,creationflags=flags)
        status = {'returncode':result.returncode,'target':target,'authenticated':False,
                  'status':'complete' if result.returncode in (0,2) and (out/'scan.json').exists() else 'failed',
                  'limits':'Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.'}
        (out/'status.json').write_text(json.dumps(status,indent=2), encoding='utf-8')
        print(json.dumps(status))
    except Exception as exc:
        (out/'status.json').write_text(json.dumps({'status':'failed','error':str(exc),'target':target},indent=2),encoding='utf-8')
        raise
    finally:
        app.terminate()
        try: app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill(); app.wait()
