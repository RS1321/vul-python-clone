"""Copy code/evidence into the user's repository; preserve its benchmark source.

No commit, push, deletion or reset is performed. Re-exports update only the
directory identified by this exporter's ownership marker.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT.parent / 'vul-python-clone'
DEST = TARGET / 'avr_pipeline'
MARKER = DEST / 'EXPORT_MANIFEST.json'
EXCLUDED = {'.git', '.venv', '.review-work', 'benchmarks', '__pycache__', '.pytest_cache',
            'source', 'codeql-db', 'zap-home', 'target-state', 'tests', 'synthetic-A-checkpoint-source'}
TOP = {'llm', 'context_builder', 'review', 'review_tests', 'review_results', 'continuation'}
FILES = {'README.md', 'requirements-review.txt', '.gitignore', '.env.example'}
EXTENSIONS = {'.py', '.json', '.md', '.txt', '.log', '.xml', '.diff', '.patch', '.yaml', '.yml',
              '.sarif', '.toml', '.ini', '.ps1', '.csv', '.example', '.tap'}
KEY_PATTERN = r'AIza[0-9A-Za-z_-]{30,}|sk-(?:proj-|or-v1-)?[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16}'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    remote = subprocess.check_output(['git', '-C', str(TARGET), 'remote', 'get-url', 'origin'], text=True).strip()
    if remote.removesuffix('.git').lower() != 'https://github.com/rs1321/vul-python-clone':
        raise ValueError('Export is confined to the explicitly named user repository')
    if DEST.exists() and not MARKER.exists():
        raise ValueError('Existing destination has no exporter marker; refusing to overwrite')
    if DEST.is_symlink() or not DEST.resolve().is_relative_to(TARGET.resolve()):
        raise ValueError('Destination escapes the user repository')
    previous = json.loads(MARKER.read_text()) if MARKER.exists() else {}
    for item in previous.get('files', []):
        existing = DEST / item['path']
        if not existing.resolve().is_relative_to(DEST.resolve()):
            raise ValueError('Previous export marker escapes its directory')
        if existing.exists() and digest(existing.read_bytes()) != item['export_sha256']:
            raise ValueError('Exported file was edited separately; preserving it: ' + item['path'])
    DEST.mkdir(exist_ok=True)
    MARKER.write_text(json.dumps({'state': 'export_in_progress', 'created_by': 'continuation/export_to_user_repo.py'}), encoding='utf-8')
    credentials = [v.encode() for k, v in os.environ.items() if len(v) >= 12 and
                   re.search(r'api.?key|token|secret|password|credential|access.?key', k, re.I)]
    records = []
    for folder, dirs, files in os.walk(ROOT):
        parent = Path(folder)
        relative_dir = parent.relative_to(ROOT)
        dirs[:] = [d for d in dirs if d not in EXCLUDED and (relative_dir.parts or d in TOP)]
        for name in sorted(files):
            source = parent / name
            relative = source.relative_to(ROOT)
            if (not relative_dir.parts and name not in FILES) or name == '.env' or name.startswith('.coverage'):
                continue
            if source.suffix not in EXTENSIONS and name not in FILES:
                continue
            if not source.resolve().is_relative_to(ROOT.resolve()):
                raise ValueError('Source link escapes the project')
            data = source.read_bytes()
            original_sha = digest(data)
            redactions = 0
            for value in credentials:
                if value in data:
                    data = data.replace(value, b'REDACTED_LOCAL_CREDENTIAL')
                    redactions += 1
            data, count = re.subn(KEY_PATTERN.encode('ascii'), b'REDACTED_BENCHMARK_CREDENTIAL', data)
            path_redactions = 0
            target = DEST / relative
            if target.is_symlink() or not target.resolve().is_relative_to(DEST.resolve()):
                raise ValueError('Export path escapes owned directory')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records.append({'path': relative.as_posix(), 'source_sha256': original_sha,
                            'export_sha256': digest(data), 'redactions': redactions + count,
                            'workspace_path_redactions': path_redactions})
    # Raw scanner-input and implementation digests must survive Git checkout
    # on Windows, including when the user's global autocrlf setting is enabled.
    attributes = b'* -text\n'
    (DEST / '.gitattributes').write_bytes(attributes)
    records.append({'path': '.gitattributes', 'source_sha256': digest(attributes),
                    'export_sha256': digest(attributes), 'redactions': 0,
                    'workspace_path_redactions': 0, 'generated_by': 'export_to_user_repo.py'})
    marker = {'source_url': 'https://github.com/Deep-Jiwan/AVR-System',
              'upstream_commit': 'f411f88440be3439c1a95e06e2abc493dbe7ab22',
              'application_baseline_commit': '1a23c1dbc0dd843c294036c077ea2a7538a45790',
              'scope': 'Local code/evidence export. Runtime clones, credentials, model weights and databases omitted.',
              'redaction_note': 'Redacted artifacts may require re-fetching the pinned public input for byte-exact reproduction.',
              'files': records}
    MARKER.write_text(json.dumps(marker, indent=2), encoding='utf-8')
    guide = TARGET / 'AVR_REVIEW_CHANGES.md'
    guide.write_text('# Reviewer-driven code revision\n\n'
        'The repair pipeline and measured evidence are in [avr_pipeline](avr_pipeline/README.md). '
        'Read [the current code response](avr_pipeline/continuation/results/CODE_REVIEW_RESPONSE.md) for completed and unavailable results.\n\n'
        'The original vulnerable application is preserved as a benchmark. New runs must use its pinned original commit, '
        'not scan this larger repository containing the pipeline. From avr_pipeline, run '
        '`python review/prepare_inputs.py` to create the separate benchmark clones.\n\n'
        'The user deferred manuscript changes. Source authorship was audited, but original expert-review provenance '
        'and independent human signoff were not established.\n', encoding='utf-8')
    print(json.dumps({'destination': str(DEST), 'files': len(records),
                      'redacted_files': sum(r['redactions'] > 0 for r in records)}))


if __name__ == '__main__':
    main()
