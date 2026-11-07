"""A labeled synthetic, generated two-module contract-change pilot."""
import ast
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'llm'), str(ROOT / 'context_builder')]
from llm_client import LLMClient
from llm.patchset import apply_patchset, sha256
from egress_guard import sanitise
from review.runner import command, dump

out = ROOT / 'continuation/results/multifile-pilot'
if out.exists():
    raise ValueError('Use a fresh pilot directory')
source = out / 'source'
source.mkdir(parents=True)
original = {'encoder.py': 'def encode(value):\n    return {"legacy": value}\n',
            'decoder.py': 'def decode(value):\n    return value["legacy"]\n'}
for path, text in original.items():
    (source / path).write_bytes(text.encode())
test = '''from encoder import encode
from decoder import decode
for value in [None, 42, 'sample', {'name': ['one', 'two']}]:
    assert decode(encode(value)) == value
    assert encode(value) == {'version': 2, 'payload': value}
try:
    decode({'version': 99, 'payload': 'sample'})
except ValueError:
    pass
else:
    raise AssertionError('Unknown versions must be rejected')
print('4 round trips, 4 format contracts, 1 invalid-version contract passed')
'''
def validate(root):
    proc = command([sys.executable, '-B', '-c', test], cwd=root, timeout=30)
    return {'passed': proc.returncode == 0, 'returncode': proc.returncode,
            'output': proc.stdout, 'error': proc.stderr[-2000:]}
dump(out / 'baseline-target-contracts.json', validate(source))
prompt = sanitise('Perform a coordinated format migration in this synthetic two-module fixture. '
    'encode(value) must return {"version":2,"payload":value}; decode must round-trip it and raise ValueError '
    'for other version values. Preserve function names. Each file must contain only its existing function. '
    'Return JSON {"files":[{"path":"encoder.py","after":"complete source"}, '
    '{"path":"decoder.py","after":"complete source"}]}. No tests, commands or explanation.\n' + json.dumps(original))
(out / 'prompt.txt').write_text(prompt, encoding='utf-8')
response = LLMClient('gemini', 'gemini-3.5-flash-lite', max_tokens=4096).chat_completion([{'role': 'user', 'content': prompt}])
dump(out / 'response.json', response)
content = re.sub(r'^```(?:json)?\s*|\s*```$', '', response['content'].strip())
files = json.loads(content)['files']
if len(files) != 2 or {f['path'] for f in files} != set(original):
    raise ValueError('Expected both named files exactly once')
edits = []
for file in files:
    tree = ast.parse(file['after'])
    expected_name = 'encode' if file['path'] == 'encoder.py' else 'decode'
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != expected_name:
        raise ValueError('Unexpected top-level source structure')
    before = (source / file['path']).read_bytes()
    edits.append({'path': file['path'], 'sha256': sha256(before), 'before': before.decode(), 'after': file['after']})
dump(out / 'proposed-edits.json', edits)
result = apply_patchset(source, edits, validate)
result.update(model=response['model'], attempts=1,
              scope='Synthetic generated two-file contract migration; not a vulnerability fix rate or production benchmark')
dump(out / 'result.json', result)
print(json.dumps({'accepted': result['accepted'], 'changed_files': len(result['files']), 'scope': result['scope']}))
