"""Actual production two-module necessity, rollback and source-drift checks."""
import json
from pathlib import Path
import sys

import production_evaluation as study

ROOT = study.ROOT
OUT = ROOT / 'continuation/results/completion/multifile-production'


def main():
    candidate = ROOT / 'continuation/results/completion/production-feedback/urllib3-303/r2'
    completed = json.loads((candidate / 'result.json').read_text())
    if not completed.get('accepted'):
        raise RuntimeError('The recorded r2 candidate must pass first')
    proposals = sorted(candidate.glob('attempt-*/proposed-edits.json'))
    edits = json.loads(proposals[-1].read_text())
    rows = []
    for label, selected in [('connectionpool-only', edits[:1]), ('poolmanager-only', edits[1:]), ('both-modules', edits)]:
        folder = OUT / label
        source = study.clone('urllib3-303', folder, study.CASES['urllib3-303']['baseline'])
        snapshots = {p['path']: (source / p['path']).read_bytes() for p in edits}
        result = study.apply_patchset(source, selected, lambda repo: study.oracle('urllib3-303', repo, folder / 'validation'))
        result.update(label=label, unchanged_after_rejection=all((source / p).read_bytes() == raw for p, raw in snapshots.items()) if not result['accepted'] else None)
        if result['accepted'] != (label == 'both-modules'):
            raise AssertionError('Two-module necessity control failed: ' + label)
        if not result['accepted'] and not result['unchanged_after_rejection']:
            raise AssertionError('Rollback changed a file')
        study.dump(folder / 'result.json', result)
        rows.append(result)
    folder = OUT / 'source-drift'
    source = study.clone('urllib3-303', folder, study.CASES['urllib3-303']['baseline'])
    target = source / edits[0]['path']
    target.write_bytes(b'# Owner-inserted drift fixture before original module.\n' + target.read_bytes())
    before = {p['path']: (source / p['path']).read_bytes() for p in edits}
    stale = study.apply_patchset(source, edits, lambda _: {'passed': True})
    if stale['accepted'] or any((source / p).read_bytes() != raw for p, raw in before.items()):
        raise AssertionError('Stale proposal was not rejected before writes')
    fresh = [dict(p, sha256=study.sha256((source / p['path']).read_bytes())) for p in edits]
    refreshed = study.apply_patchset(source, fresh, lambda repo: study.oracle('urllib3-303', repo, folder / 'validation'))
    if not refreshed['accepted']:
        raise AssertionError('Re-fetched proposal did not survive line drift')
    drift = dict(label='source-drift', stale=stale, refreshed=refreshed,
                 scope='Owner inserted one comment; re-fetch rebounded exact fragments/digests. No semantic concurrent merge claim.')
    study.dump(folder / 'result.json', drift)
    rows.append(drift)
    study.dump(OUT / 'summary.json', rows)
    print(json.dumps({'partial_changes_rejected': 2, 'full_change_accepted': True, 'stale_rejected': True, 'refetched_accepted': True}))


if __name__ == '__main__':
    main()
