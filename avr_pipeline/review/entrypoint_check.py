"""Check ordinary benchmark startup with Flask.run mocked; no server is opened."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
from unittest.mock import patch

parser = argparse.ArgumentParser()
parser.add_argument('--repo', required=True, type=Path)
parser.add_argument('--out', required=True, type=Path)
args = parser.parse_args()
source = args.repo.resolve() / 'vulnerable_app.py'
out = args.out.resolve()
if out.exists() or out.is_relative_to(args.repo.resolve()):
    raise ValueError('Use a fresh runtime folder outside source')
out.mkdir(parents=True)
os.chdir(out)
calls = []
def serve(app, *positional, **kwargs):
    calls.append({'host': kwargs.get('host'), 'port': kwargs.get('port'), 'debug': kwargs.get('debug')})
captured = io.StringIO()
try:
    with patch('flask.Flask.run', serve), contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        runpy.run_path(str(source), run_name='__main__')
    passed = len(calls) == 1 and calls[0]['port'] == 3000 and calls[0]['host'] in (None, '127.0.0.1', 'localhost')
    result = {'passed': passed, 'server_calls': calls}
except Exception as exc:
    result = {'passed': False, 'error': type(exc).__name__ + ': ' + str(exc)}
result.update(scope='Startup control-flow check with mocked server; not a network or security oracle',
              source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
(out / 'startup.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
(out / 'startup.log').write_text(captured.getvalue(), encoding='utf-8')
print(json.dumps(result))
raise SystemExit(0 if result['passed'] else 1)
