"""Explicit transport-only source variants; preserve every original fingerprint.

Only the declared shorter-timeout implementation is compatible. Completed replies
execute identical prompts, sampling, patching, gates and tests. Interrupted cells
remain incomplete, and acknowledged generations across resumes must obey caps.
"""
from collections import Counter
import json
from review.continuation_state import verify_generation_reference


def compatible_variants(protocol):
    return protocol.get('transport_only_compatible_implementations', [])+protocol.get('continuation_only_compatible_implementations', [])


def matches_implementation(manifest, protocol):
    fingerprints = manifest.get('implementation_sha256')
    return fingerprints == protocol['primary_implementation_sha256'] or any(
        fingerprints == variant['implementation_sha256'] and
        (not variant.get('providers') or manifest.get('provider') in variant['providers'])
        for variant in compatible_variants(protocol))


def runner_hashes(protocol, provider=None):
    maps = [protocol['primary_implementation_sha256']]+[
        v['implementation_sha256'] for v in compatible_variants(protocol)
        if provider is None or not v.get('providers') or provider in v['providers']]
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
    counts, errors = Counter(), []
    for result in records:
        for attempt in result.get('attempts', []):
            if attempt.get('response') is None:
                continue
            if attempt.get('continued_generation'):
                try:
                    verify_generation_reference(run,attempt)
                except Exception:
                    errors.append({'finding':result['finding_id'],'reason':'invalid continued-generation evidence'})
            else:
                counts[result['finding_id']] += 1
    cap = manifest.get('settings',{}).get('attempts', 0)
    return errors+[{'finding':finding,'acknowledged_generations':count,'cap':cap}
            for finding,count in counts.items() if cap and count > cap]
