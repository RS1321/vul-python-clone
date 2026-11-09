"""Explicit transport-only source variants; preserve every original fingerprint.

Only the declared shorter-timeout implementation is compatible. Completed replies
execute identical prompts, sampling, patching, gates and tests. Interrupted cells
remain incomplete, and acknowledged generations across resumes must obey caps.
"""
from collections import Counter
import json


def matches_implementation(manifest, protocol):
    fingerprints = manifest.get('implementation_sha256')
    return fingerprints == protocol['primary_implementation_sha256'] or any(
        fingerprints == variant['implementation_sha256']
        for variant in protocol.get('transport_only_compatible_implementations', []))


def runner_hashes(protocol):
    maps = [protocol['primary_implementation_sha256']]+[
        v['implementation_sha256'] for v in protocol.get('transport_only_compatible_implementations', [])]
    return {m.get('review/runner.py') for m in maps}


def budget_violations(run):
    manifest = json.loads((run/'manifest.json').read_text())
    if manifest.get('condition') == 'tool_agent':
        cap = manifest.get('settings',{}).get('max_turns')
        return ['tool turn cap exceeded'] if cap and len(list(run.glob('turn-*.json'))) > cap else []
    path = run/'results.json'
    if not path.exists():
        return []
    records = json.loads(path.read_text())
    for saved in run.glob('interrupted-finding-*.json'):
        records.append(json.loads(saved.read_text()))
    counts = Counter()
    for result in records:
        counts[result['finding_id']] += sum(a.get('response') is not None for a in result.get('attempts', []))
    cap = manifest.get('settings',{}).get('attempts', 0)
    return [{'finding':finding,'acknowledged_generations':count,'cap':cap}
            for finding,count in counts.items() if cap and count > cap]
