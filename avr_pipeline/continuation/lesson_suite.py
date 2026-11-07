"""Baseline/hardened coverage of every pinned PyGoat lesson directory."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'continuation/results/security-resolution-v6/lesson-tests-final2'
REPAIRED=ROOT/'continuation/results/security-resolution-v6/pygoat/source'


def main():
    env={k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential',k,re.I)}
    jobs=[]
    for state,repo in [('baseline',ROOT/'benchmarks/pygoat'),('hardened',REPAIRED)]:
        for folder in sorted((repo/'dockerized_labs').iterdir()):
            if folder.is_dir():jobs.append((state,repo,folder.name))
    def work(job):
        state,repo,lesson=job;out=OUT/state/lesson;record=out/'checks.json'
        if not out.exists():
            runtime='pygoat' if lesson=='sensitive_data_exposure' else 'vampi'
            script='data_exposure_security.py' if lesson=='sensitive_data_exposure' else 'lesson_security.py'
            cmd=[str(ROOT/f'.review-work/{runtime}-env/Scripts/python.exe'),str(ROOT/'review'/script),'--repo',str(repo),'--out',str(out)]
            if lesson!='sensitive_data_exposure':cmd+=['--lesson',lesson]
            proc=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,env=env,timeout=90)
            out.mkdir(parents=True,exist_ok=True);(out/'runner.log').write_text(proc.stdout+proc.stderr,encoding='utf-8')
        data=json.loads(record.read_text()) if record.exists() else {'passed':False,'harness_error':True}
        print(state,lesson,data['passed'],data.get('harness_error',''),flush=True)
        return dict(state=state,lesson=lesson,result=data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(work,jobs))
    (OUT/'summary.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')


if __name__=='__main__':main()
