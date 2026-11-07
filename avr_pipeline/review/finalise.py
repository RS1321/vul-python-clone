"""Refresh evidence tables and the ZIP after selected local runs finish."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--suite',type=Path,action='append',default=[])
parser.add_argument('--run',type=Path,action='append',default=[])
parser.add_argument('--timeout',type=int,default=3600)
args=parser.parse_args()


def ready():
    if any(not p.exists() for p in args.suite): return False
    for path in args.run:
        try:
            if json.loads(path.read_text(encoding='utf-8')).get('status')=='running': return False
        except (OSError,ValueError):
            return False
    return True


deadline=time.monotonic()+args.timeout
while not ready() and time.monotonic()<deadline:
    time.sleep(20)
if not ready():
    print('Wait expired; packaging recorded results only',flush=True)
for name in ('vampi_regex_check','aggregate_effects','report','package_results'):
    subprocess.run([sys.executable,str(root/'review'/f'{name}.py')],cwd=root,check=True)
