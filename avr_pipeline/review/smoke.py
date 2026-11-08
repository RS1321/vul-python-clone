"""Offline pipeline smoke: exact snapshot patching, with no provider/scanner claim."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import repair_one, CONDITIONS, dump


class FixtureClient:
    def chat_completion(self, *args, **kwargs):
        return {'model': 'offline-fixture', 'content': 'SCOPE: function\n```python\ndef f():\n    return 2\n```', 'usage': {}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, default=ROOT/'.review-work/smoke')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.out) as temp:
        repo = Path(temp)
        (repo/'app.py').write_text('def f():\n    return 1\n')
        finding = {'finding_id': 'offline-fixture', 'sast': {'cwe': 'CWE-089', 'rule_id': 'fixture',
                   'description': 'Offline wiring check', 'location': {'file_path': 'app.py', 'function': 'f', 'start_line': 1, 'end_line': 2}}}
        library = json.loads((ROOT/'llm/guidance_library.review-2.json').read_text())
        result = repair_one(repo, finding, CONDITIONS['C'], FixtureClient(), [], {}, args.out/'attempts', prompt_library=library)
        assert result['accepted'] and 'return 2' in (repo/'app.py').read_text()
    dump(args.out/'smoke.json', {'status': 'passed', 'provider': 'offline-fixture',
         'scope': 'Patch wiring only; not a model experiment or SAST/DAST measurement'})
    print('Offline pipeline smoke passed')


if __name__ == '__main__':
    main()
