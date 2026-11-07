"""Bounded resumable five-model evaluation, one worker per model."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from review.runner import dump
from review.project_paths import synthetic_repo
MODELS=['gemma-4-26b-a4b-it','gemma-4-31b-it','gemini-3.1-flash-lite','gemini-3.5-flash-lite','qwen2.5-coder-1.5b-instruct-q4km']
env=dict(os.environ,AVR_INPUT_BUDGET_PER_MINUTE='12000',AVR_REQUEST_TIMEOUT='60',AVR_TRANSPORT_RETRIES='2')
OUTPUT=ROOT/'continuation/results'
OUTPUT.mkdir(parents=True,exist_ok=True)


def worker(model, tasks=None):
    records=[]
    # Same compact protocol and library for every model and comparison.
    tasks=tasks or [('synthetic','A'),('synthetic','B'),('pygoat','A'),('vampi','A')]
    for dataset,condition in tasks:
        repo=synthetic_repo() if dataset=='synthetic' else ROOT/'benchmarks'/dataset
        out=ROOT/'review_results'/f'{model}-{condition}-{dataset}-fivefree-v2-r1'
        out.mkdir(parents=True,exist_ok=True)
        manifest=out/'manifest.json'
        for cycle in range(6):
            prior=json.loads(manifest.read_text()) if manifest.exists() else {}
            if prior.get('status')=='complete': break
            if prior.get('status')=='running':
                raise RuntimeError(f'Another worker owns {out.name}')
            args=[sys.executable,str(ROOT/'review/runner.py'),'run','--repo',str(repo),
                  '--sarif',str(ROOT/'review_results'/f'baseline-{dataset}'/'scan.sarif'),
                  '--out',str(out),'--model',model,'--condition',condition,
                  '--context-profile','compact','--rescan','--provider','local' if model.startswith('qwen') else 'gemini']
            if prior and (out/'results.json').exists(): args.append('--resume')
            with (out/'supervisor.log').open('a',encoding='utf-8') as log:
                log.write(f'\nCycle {cycle+1}\n');log.flush()
                subprocess.run(args,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
            state=json.loads(manifest.read_text()) if manifest.exists() else {'status':'launch_error'}
            print(model,dataset,condition,state['status'],state.get('processed_findings'),flush=True)
            if state['status']=='complete': break
            if state['status']!='interrupted_api_error': break
            if cycle<5: time.sleep(30)
        records.append({'dataset':dataset,'condition':condition,'run':out.name,
                        'status':json.loads(manifest.read_text()).get('status') if manifest.exists() else 'launch_error'})
        dump(OUTPUT/(model+'-progress.json'),records)
    return records


if __name__=='__main__':
    subprocess.run([sys.executable,str(ROOT/'continuation/audit_public_inputs.py')],cwd=ROOT,check=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures={pool.submit(worker,m):m for m in MODELS}
        for f in concurrent.futures.as_completed(futures):
            try: result=f.result()
            except Exception as exc: result={'error':str(exc)}
            dump(OUTPUT/(futures[f]+'-final.json'),result)
