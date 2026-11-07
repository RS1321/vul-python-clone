"""Execute selected matrix cells locally; each cell has a new source clone."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from review.runner import CONDITIONS
from review.project_paths import synthetic_repo

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dataset',choices=('synthetic','pygoat','vampi'),required=True)
parser.add_argument('--model',nargs='+',required=True)
parser.add_argument('--conditions',nargs='+',choices=list(CONDITIONS),required=True)
parser.add_argument('--repetitions',type=int,default=1)
parser.add_argument('--jobs',type=int,default=1,choices=(1,2))
parser.add_argument('--tag',required=True)
parser.add_argument('--provider',choices=('gemini','openrouter','ollama','local'),default='gemini')
args=parser.parse_args()
if not args.tag.replace('-','').isalnum() or args.repetitions < 1:
    parser.error('Use a simple alphanumeric tag and a positive repetition count')
if any(not model.replace('-','').replace('.','').replace('/','').replace(':','').isalnum() for model in args.model):
    parser.error('Invalid model identifier')
repo=synthetic_repo() if args.dataset=='synthetic' else ROOT/'benchmarks'/args.dataset
results=ROOT/'review_results'
baseline=results/f'baseline-{args.dataset}/scan.sarif'
if not baseline.is_file(): parser.error(f'Baseline scan missing: {baseline}')


def execute(cell):
    model,condition,repetition=cell
    stem=model.replace('/','-').replace(':','-')
    out=results/f'{stem}-{condition}-{args.dataset}-{args.tag}-r{repetition}'
    out.mkdir(parents=True,exist_ok=True)
    manifest=out/'manifest.json'
    if manifest.exists():
        status=json.loads(manifest.read_text()).get('status')
        if status in ('running','complete'):
            return {'run':out.name,'status':'already_'+status}
    cli=[sys.executable,str(ROOT/'review/runner.py'),'run','--repo',str(repo),'--sarif',str(baseline),
         '--out',str(out),'--model',model,'--condition',condition,'--provider',args.provider,
         '--repetition',str(repetition),'--rescan']
    if manifest.exists() and (out/'results.json').exists(): cli.append('--resume')
    print('Starting',out.name,flush=True)
    with (out/'runner.log').open('a',encoding='utf-8') as log:
        log.write(f'\nStarted {datetime.now(timezone.utc).isoformat()}\n');log.flush()
        result=subprocess.run(cli,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
    record=json.loads(manifest.read_text()) if manifest.exists() else {}
    status={'run':out.name,'status':record.get('status','runner_failed'),'returncode':result.returncode}
    print(json.dumps(status),flush=True)
    return status


cells=[(m,c,r) for r in range(1,args.repetitions+1) for c in args.conditions for m in args.model]
with ThreadPoolExecutor(max_workers=args.jobs) as executor:
    outputs=list(executor.map(execute,cells))
(results/f'suite-{args.dataset}-{args.tag}.json').write_text(json.dumps(outputs,indent=2),encoding='utf-8')
