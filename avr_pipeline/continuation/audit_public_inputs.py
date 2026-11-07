"""Read-only proof that sweep inputs match public, pinned, tracked source."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'llm')]
from review.runner import contexts,dump
from review.project_paths import synthetic_repo
from egress_guard import check_messages,sanitise,PATTERN
import re
allowed={'synthetic':'https://github.com/RS1321/vul-python-clone',
         'pygoat':'https://github.com/adeyosemanputra/pygoat',
         'vampi':'https://github.com/erev0s/VAmPI'}
rows=[]
for name,url in allowed.items():
 repo=synthetic_repo() if name=='synthetic' else ROOT/'benchmarks'/name
 run=lambda *args:subprocess.check_output(['git','-C',str(repo),*args])
 remote=run('remote','get-url','origin').decode().strip().removesuffix('.git')
 assert remote.lower()==url.lower(),remote
 saved=json.loads((ROOT/f'review_results/baseline-{name}/dataset-manifest.json').read_text())
 sha=run('rev-parse','HEAD').decode().strip();assert sha==saved['source_commit']
 findings=contexts(repo,ROOT/f'review_results/baseline-{name}/scan.sarif')
 paths=sorted({f['sast']['location']['file_path'] for f in findings})
 files=[]
 for relative in paths:
  run('ls-files','--error-unmatch',relative)
  blob=run('show',f'HEAD:{relative}').replace(b'\r\n',b'\n')
  local=(repo/relative).read_bytes().replace(b'\r\n',b'\n')
  assert blob==local,f'Uncommitted source: {relative}'
  original=local.decode('utf-8');clean=sanitise(original)
  check_messages([{'role':'user','content':clean}])
  files.append({'path':relative,'sha256':hashlib.sha256(local).hexdigest(),
                'sanitised_sha256':hashlib.sha256(clean.encode()).hexdigest(),
                'redactions':len(re.findall(PATTERN,original))})
 rows.append({'dataset':name,'public_url':url,'commit':sha,'tracked_files':files,
              'findings':len(findings),'credential_guard':'passed','destination':'Google Gemini API'})
dump(ROOT/'continuation/results/public-input-audit.json',rows)
print('Public tracked-source and credential checks passed for',[(r['dataset'],len(r['tracked_files'])) for r in rows])
