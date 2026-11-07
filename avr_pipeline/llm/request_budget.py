"""Shared conservative request pacing; contains no credentials."""
import hashlib
import json
import math
import os
from pathlib import Path
import time
if os.name == 'nt':
    import msvcrt
else:
    import fcntl


def acquire(handle):
    if os.name == 'nt':
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def release(handle):
    if os.name == 'nt':
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def reserve(model, contents):
    capacity=int(os.getenv('AVR_INPUT_BUDGET_PER_MINUTE','0'))
    if not capacity: return 0
    tokens=math.ceil(len(json.dumps(contents,ensure_ascii=False))/2)+128
    if tokens>capacity:
        raise RuntimeError(f'Gemini input budget exceeded before request: estimated {tokens}, allowed {capacity}; use compact context')
    root=Path(__file__).resolve().parents[1]/'.review-work/request-budget'
    root.mkdir(parents=True,exist_ok=True)
    stem=hashlib.sha256(model.encode()).hexdigest()[:16]
    ledger=root/(stem+'.json');lock=root/(stem+'.lock')
    start=time.monotonic()
    while True:
        with lock.open('a+b') as handle:
            if handle.tell()==0: handle.write(b'0');handle.flush()
            handle.seek(0);acquire(handle)
            try:
                now=time.time()
                rows=json.loads(ledger.read_text()) if ledger.exists() else []
                rows=[r for r in rows if now-r['time']<61]
                if sum(r['tokens'] for r in rows)+tokens<=capacity:
                    rows.append({'time':now,'tokens':tokens})
                    ledger.write_text(json.dumps(rows),encoding='utf-8')
                    return round(time.monotonic()-start,3)
                delay=max(1,min(30,62-(now-min(r['time'] for r in rows))))
            finally:
                handle.seek(0);release(handle)
        time.sleep(delay)
