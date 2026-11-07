"""Bounded isolated regex timing and input-behaviour checks from VAmPI source."""
import ast
import csv
import json
from pathlib import Path
import re
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sources={'baseline':ROOT/'benchmarks/vampi/api_views/users.py',
         'Gemma 26B A':ROOT/'review_results/gemma26-A-vampi-r1/source/api_views/users.py',
         'Gemma 26B simple':ROOT/'review_results/gemma26-simple-vampi-r1/source/api_views/users.py',
         'Gemma 31B A':ROOT/'review_results/gemma31-A-vampi-r1/source/api_views/users.py'}


def patterns(path):
    module=ast.parse(path.read_text(encoding='utf-8'))
    function=next(n for n in ast.walk(module) if isinstance(n,ast.FunctionDef) and n.name=='update_email')
    # Only extract regex constants, never execute patched application code.
    found=[]
    for node in ast.walk(function):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in ('search','fullmatch','compile') and node.args:
            arg=node.args[0]
            if isinstance(arg,ast.Constant) and isinstance(arg.value,str): found.append((node.lineno,node.func.attr,arg.value))
        elif isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str) and any(isinstance(t,ast.Name) and t.id=='regex' for t in node.targets):
            found.append((node.lineno,'search',node.value.value))
    return sorted(found)


rows=[]
if not sources['baseline'].exists() or not any(p.exists() for name,p in sources.items() if name!='baseline'):
    print('VAmPI source is unavailable; preserving the recorded regex results')
    sys.exit(0)
inputs={'normal address':'alice@example.com','host without dot':'alice@localhost',
        'invalid address':'alice@@example.com','bounded near miss':'a'*18+'@invalid!'}
for label,path in sources.items():
    if not path.exists(): continue
    manifest=path.parents[2]/'manifest.json' if label!='baseline' else None
    if manifest and (not manifest.exists() or json.loads(manifest.read_text()).get('status')!='complete'):
        continue
    for i,(line,operation,pattern) in enumerate(patterns(path),1):
        compiled=re.compile(pattern)
        call=compiled.fullmatch if operation=='fullmatch' else compiled.search
        for name,value in inputs.items():
            times=[]
            for _ in range(5):
                start=time.perf_counter_ns(); matched=bool(call(value)); times.append((time.perf_counter_ns()-start)/1000)
            rows.append({'variant':label,'pattern':i,'source_line':line,'input':name,
                         'matched':matched,'median_microseconds':round(statistics.median(times),2)})
with (ROOT/'review_results/vampi-regex-check.csv').open('w',encoding='utf-8',newline='') as handle:
    writer=csv.DictWriter(handle,fieldnames=list(rows[0])); writer.writeheader();writer.writerows(rows)
print(f'Wrote {len(rows)} bounded regex checks; no HTTP or regression claim')
