"""Create separate pinned production inputs; never reset an existing checkout."""
from pathlib import Path
import subprocess
import production_evaluation as study

ROOT = study.ROOT
fixed = {'urllib3-cve':'9c2c2307dd1d6af504e09aac0326d86ee3597a0b',
         'minimist-cve':'7efb22a518b53b06f5b02a1038a88bd6290c2846',
         'requests-cve':'147c8511ddbfa5e8f71bbf5c18ede0c4ceb3bba4'}
for case in {c['repo']:c for c in study.CASES.values()}.values():
    repo = ROOT/'benchmarks'/case['repo']
    repo.parent.mkdir(exist_ok=True)
    if not repo.exists():
        subprocess.run(['git','clone',case['url'],str(repo)],check=True)
        subprocess.run(['git','-C',str(repo),'checkout','--detach',case['baseline']],check=True)
    if study.git(repo,'remote','get-url','origin').removesuffix('.git').lower() != case['url'].lower():
        raise ValueError('Unexpected origin')
    if study.git(repo,'rev-parse','HEAD') != case['baseline'] or study.git(repo,'status','--porcelain','--untracked-files=no'):
        raise ValueError('Preserving an existing non-baseline or modified checkout: '+str(repo))
    subprocess.run(['git','-C',str(repo),'fetch','origin','tag',case['fixed']],check=True)
    if study.git(repo,'rev-parse',case['fixed']+'^{commit}') != fixed[case['repo']]:
        raise ValueError('Maintainer reference changed')
    print(case['repo'],case['baseline'],fixed[case['repo']])
