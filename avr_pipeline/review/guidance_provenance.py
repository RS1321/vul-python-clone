"""Record available authorship evidence without inventing review identities."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True, encoding='utf-8', errors='replace').strip()


def main():
    tracked = git('ls-tree', '-r', '--name-only', 'HEAD').splitlines()
    candidates = [p for p in tracked if 'prompt' in p.lower() or 'guidance' in p.lower()]
    records = []
    for path in candidates:
        raw = subprocess.check_output(['git', '-C', str(ROOT), 'show', 'HEAD:' + path])
        records.append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'history': git('log', '--all', '--format=%H %an %aI %s', '--', path),
                        'blame_authors': sorted({line[7:] for line in git('blame', '--line-porcelain', 'HEAD', '--', path).splitlines() if line.startswith('author ')})})
    result = {'source_url': git('remote', 'get-url', 'origin'),
              'source_commit': git('rev-parse', 'HEAD'), 'records': records,
              'evidence_examined': ['available local Git history across fetched refs', 'tracked prompt/guidance sources'],
              'original_expert_review_provenance': 'not established by the available records',
              'interpretation': 'Commit authorship identifies source authorship, not expert validation. Absence of signoffs in this checkout does not prove that no review took place.',
              'revision_library': 'One before/after pair per CWE, supplied per CWE rather than per finding; 18 entries chosen for the original scope and retained for comparison. New entries are authored during this revision.',
              'independent_human_review': 'No reviewer names, qualifications, signoffs or review records supplied.'}
    out = ROOT / 'continuation/results/guidance-provenance.json'
    out.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print('Recorded prompt histories:', len(records), '; expert review provenance: unestablished')


if __name__ == '__main__':
    main()
