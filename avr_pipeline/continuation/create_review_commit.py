"""Commit the verified export on a review branch without changing benchmark HEAD."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent / 'vul-python-clone'
BRANCH = 'refs/heads/codex/reviewer-code-revision'
STATE = ROOT / '.review-work/review-branch-state.json'


def git(*args, env=None, check=True):
    proc = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True,
                          encoding='utf-8', errors='replace', env=env)
    if check and proc.returncode:
        raise RuntimeError(proc.stderr[-2000:])
    return proc


def main():
    marker = json.loads((REPO / 'avr_pipeline/EXPORT_MANIFEST.json').read_text())
    if not marker.get('files') or marker['application_baseline_commit'] != '1a23c1dbc0dd843c294036c077ea2a7538a45790':
        raise ValueError('Verified export is required')
    if git('remote', 'get-url', 'origin').stdout.strip().removesuffix('.git').lower() != 'https://github.com/rs1321/vul-python-clone':
        raise ValueError('Wrong target repository')
    head = git('rev-parse', 'HEAD').stdout.strip()
    current = git('rev-parse', '--verify', BRANCH, check=False)
    previous = current.stdout.strip() if current.returncode == 0 else None
    saved = json.loads(STATE.read_text()) if STATE.exists() else {}
    if previous and saved.get('commit') != previous:
        raise ValueError('Review branch changed outside this export; refusing to overwrite')
    parent = previous or head
    env = dict(os.environ, GIT_INDEX_FILE=str(ROOT / '.review-work' / f'review-index-{time.time_ns()}'))
    # Existing Git identity is retained. A missing identity uses an explicit
    # local agent identity, without modifying the user's Git configuration.
    if git('var', 'GIT_AUTHOR_IDENT', check=False).returncode:
        env.update(GIT_AUTHOR_NAME='Codex', GIT_AUTHOR_EMAIL='codex@localhost',
                   GIT_COMMITTER_NAME='Codex', GIT_COMMITTER_EMAIL='codex@localhost')
    git('read-tree', parent, env=env)
    paths = ['AVR_REVIEW_CHANGES.md', '.github/workflows/avr-pipeline-checks.yml', 'avr_pipeline/EXPORT_MANIFEST.json']
    for item in marker['files']:
        file = REPO / 'avr_pipeline' / item['path']
        if not file.resolve().is_relative_to((REPO / 'avr_pipeline').resolve()):
            raise ValueError('Marker path escapes the owned export')
        import hashlib
        if hashlib.sha256(file.read_bytes()).hexdigest() != item['export_sha256']:
            raise ValueError('Export changed after verification: ' + item['path'])
        paths.append('avr_pipeline/' + item['path'])
    pathspec = ROOT / '.review-work' / f'review-paths-{time.time_ns()}.nul'
    pathspec.write_bytes(b'\0'.join(p.encode('utf-8') for p in paths) + b'\0')
    # Stage only generated, verified files; preserve unrelated user additions.
    git('--literal-pathspecs', 'add', '--force', '--pathspec-from-file=' + str(pathspec), '--pathspec-file-nul', env=env)
    tree = git('write-tree', env=env).stdout.strip()
    if tree == git('rev-parse', parent + '^{tree}').stdout.strip():
        print('No new export changes'); return
    message = ROOT / '.review-work/review-commit-message.txt'
    message.write_text('Add reproducible repair pipeline and reviewer evaluation evidence\n\n'
        'Include transactional patching, strict adoption test policy, credential guards, '
        'coordinated Python/JavaScript edits and pinned benchmark setup.\n\n'
        'Record measured comparisons, ordinary application checks and bounded production '
        'pilots; incomplete experiments and unestablished expert provenance remain explicit. '
        'Manuscript revisions are deferred.\n', encoding='utf-8')
    commit = git('commit-tree', tree, '-p', parent, '-F', str(message), env=env).stdout.strip()
    git('update-ref', BRANCH, commit, previous or '0' * 40)
    if git('rev-parse', 'HEAD').stdout.strip() != head:
        raise RuntimeError('Benchmark HEAD unexpectedly changed')
    STATE.write_text(json.dumps({'branch': BRANCH, 'commit': commit, 'benchmark_head': head}, indent=2), encoding='utf-8')
    print(json.dumps({'branch': BRANCH, 'commit': commit, 'benchmark_head_preserved': head}))


if __name__ == '__main__':
    main()
