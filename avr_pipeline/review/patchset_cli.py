"""Apply coordinated proposed edits and require a project validation command.

Example: python -m review.patchset_cli --repo CLONE --edits edits.json
  --out audit-folder --check python -m pytest tests
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'llm'), str(ROOT / 'context_builder')]
from llm.patchset import apply_patchset
from review.runner import command, dump, digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--edits', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--max-changed-lines', type=int, default=100)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--check', nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out.is_relative_to(repo) or out.exists() or not args.check:
        raise ValueError('Use a fresh audit directory outside source and a project check command')
    out.mkdir(parents=True)
    edits = json.loads(args.edits.read_text(encoding='utf-8'))
    def validate(root):
        try:
            proc = command(args.check, cwd=root, timeout=args.timeout)
            (out / 'validation.log').write_text(proc.stdout + proc.stderr, encoding='utf-8')
            return {'passed': proc.returncode == 0, 'returncode': proc.returncode}
        except subprocess.TimeoutExpired:
            return {'passed': False, 'infrastructure_error': 'validation_timeout'}
    result = apply_patchset(repo, edits, validate, args.max_changed_lines)
    result.update(edits_sha256=digest(args.edits), project_command=args.check,
                  scope='syntax and project-check acceptance; not a security resolution oracle')
    dump(out / 'result.json', result)
    print(json.dumps({'accepted': result['accepted'], 'out': str(out)}))
    return 0 if result['accepted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
