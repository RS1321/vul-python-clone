"""Upstream regressions for all accepted follow-up production candidates."""
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'continuation/results/completion/upstream'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    env = {k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    candidates = [('urllib3', 'baseline', ROOT/'benchmarks/urllib3-cve'), ('minimist', 'baseline', ROOT/'benchmarks/minimist-cve')]
    for path in sorted((ROOT/'continuation/results/completion/production-feedback').glob('*/r*/result.json')):
        result = json.loads(path.read_text())
        if result.get('accepted') and (result['case'].startswith('urllib3') or result['case'].startswith('minimist')):
            candidates.append(('urllib3' if result['case'].startswith('urllib3') else 'minimist', result['case']+'-'+path.parent.name, path.parent/'source'))
    rows = []
    for library, label, repo in candidates:
        folder = OUT / library / label
        folder.mkdir(parents=True, exist_ok=True)
        if library == 'urllib3':
            python = ROOT / '.review-work/production-env/Scripts/python.exe'
            runtime_env = dict(env, PYTHONPATH=os.pathsep.join(map(str,[repo/'src',repo,ROOT/'review'])), PYTHONDONTWRITEBYTECODE='1')
            p = subprocess.run([str(python),'-m','pytest',str(repo/'test/test_retry.py'),'--noconftest','--rootdir='+str(repo),
                '-p','no:cacheprovider','-p','urllib3_retry_fixtures','-q','--tb=short','--basetemp='+str(folder/'tmp'),
                '--junitxml='+str(folder/'results.xml')],cwd=repo,env=runtime_env,capture_output=True,text=True,timeout=120)
            cases = list(ET.parse(folder/'results.xml').iter('testcase'))
            failures = [c.attrib['name'] for c in cases if c.find('failure') is not None or c.find('error') is not None]
            row = dict(library=library,state=label,tests=len(cases),failed=len(failures),failures=failures,skipped=sum(c.find('skipped') is not None for c in cases),returncode=p.returncode)
        else:
            files = sorted((repo/'test').glob('*.js'))
            runtime_env = dict(env, NODE_PATH=str(ROOT/'.review-work/minimist-test-deps/node_modules'))
            p = subprocess.run(['node','-e','for(const f of JSON.parse(process.argv[1])) require(f);',json.dumps(list(map(str,files)))],
                cwd=repo,env=runtime_env,capture_output=True,text=True,timeout=120)
            match = re.search(r'^# tests\s+(\d+)',p.stdout,re.M)
            row = dict(library=library,state=label,tests=int(match[1]) if match else None,failed=len(re.findall(r'^not ok\b',p.stdout,re.M)),
                       skipped=0,returncode=p.returncode,files=[p.name for p in files],scope='all pinned upstream test files, including proto.js')
        (folder/'output.txt').write_text(p.stdout+p.stderr,encoding='utf-8')
        rows.append(row)
        print(library,label,row['tests'],row['failed'],flush=True)
    (OUT/'summary.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')


if __name__ == '__main__':
    main()
