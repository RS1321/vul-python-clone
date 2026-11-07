"""Generate a current, code-only review response from recorded observations."""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import dump

MODELS = ['gemma-4-26b-a4b-it', 'gemma-4-31b-it', 'gemini-3.1-flash-lite',
          'gemini-3.5-flash-lite', 'qwen2.5-coder-1.5b-instruct-q4km', 'gemini-3.6-flash',
          'qwen2.5-coder-0.5b-instruct-q4km']
OUT = ROOT / 'continuation/results'


def load(path, default=None):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default


def run_row(model, dataset, condition):
    tag = 'fivefree-v3-1024' if model == 'qwen2.5-coder-0.5b-instruct-q4km' else 'fivefree-v2'
    path = ROOT / 'review_results' / f'{model}-{condition}-{dataset}-{tag}-r1'
    state, results = load(path / 'manifest.json', {}), load(path / 'results.json', [])
    complete = state.get('status') == 'complete'
    scan = state.get('sast') or {}
    return {'model': model, 'dataset': dataset, 'condition': condition,
            'run': path.name, 'status': state.get('status', 'not_run'),
            'processed': len(results), 'eligible': state.get('eligible_findings'),
            'accepted': sum(bool(r.get('accepted')) for r in results),
            'files_changed': None,
            'resolved': scan.get('resolved_findings') if complete else None,
            'new_findings': scan.get('new_findings') if complete else None,
            'resolution_rate': scan.get('resolution_rate') if complete else None,
            'post_test_failures': len(state['post_tests']['failures']) if state.get('post_tests', {}).get('failures') is not None else None,
            'context_profile': state.get('context_profile'), 'library_sha256': state.get('library_sha256'),
            'max_tokens': state.get('max_tokens'),
            'source_commit': state.get('source_commit'), 'sarif_sha256': state.get('sarif_sha256')}


def main():
    rows = [run_row(m, d, c) for m in MODELS for d, c in [('synthetic', 'A'), ('synthetic', 'B'), ('pygoat', 'A'), ('vampi', 'A')]]
    for row in rows:
        patch = ROOT / 'review_results' / row['run'] / 'net.patch'
        if patch.exists():
            row['files_changed'] = sum(line.startswith('diff --git ') for line in patch.read_text(encoding='utf-8').splitlines())
        else:
            row['files_changed'] = None
    pairs = []
    for model in MODELS:
        a, b = [next(r for r in rows if r['model'] == model and r['dataset'] == 'synthetic' and r['condition'] == c) for c in ('A', 'B')]
        matched = all(a[k] == b[k] and a[k] is not None for k in ('context_profile', 'library_sha256', 'source_commit', 'sarif_sha256', 'max_tokens'))
        measured = matched and all(r['status'] == 'complete' for r in (a, b))
        pairs.append({'model': model, 'matched': matched, 'complete': measured,
                      'A': a, 'B': b, 'A_minus_B_pp': round((a['resolution_rate'] - b['resolution_rate']) * 100, 4) if measured else None})
    dump(OUT / 'five-model-observations.json', {'generated_utc': datetime.now(timezone.utc).isoformat(),
         'protocol': 'Within-model A/B; compact context; review-1 library; one repetition; no seed. Small Qwen v3 has a 1024-token reply cap; others v2 have 8192.',
         'scope': 'New free-model cohort; not the original paper models. A minus B combines rules and examples.',
         'five_model_target_complete': sum(p['complete'] for p in pairs) >= 5, 'pairs': pairs, 'runs': rows})
    with (OUT / 'five-model-observations.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    tests = OUT / 'completion/pipeline-checks.xml'
    if not tests.exists():
        tests = OUT / 'pipeline-tests.xml'
    cases = list(ET.parse(tests).iter('testcase')) if tests.exists() else []
    failed = sum(c.find('failure') is not None or c.find('error') is not None for c in cases)
    vet = load(OUT / 'guidance-vetting.json', [])
    runtime = load(OUT / 'external-runtime-summary.json', [])
    production = [(p.parent.name, load(p)) for p in sorted(OUT.glob('production-*/result.json'))]
    multifile = load(OUT / 'multifile-pilot/result.json')
    upstream = load(OUT / 'production-upstream-tests-v2/summary.json', [])
    startup = load(OUT / 'startup-summary.json', [])
    lines = ['# Code revision: evidence and remaining limits', '',
      'The expanded follow-up measurements are in [External and production evaluation](completion/EXPANDED_EVALUATION.md). '
      'That report adds authenticated application checks and passive ZAP measurements, repeated production security trials in Python/JavaScript, and a real two-module repair with rollback/drift controls. '
      'The historical pilot sections below remain for comparison; their missing measurements are superseded only within the exact follow-up scope.', '',
      'The user deferred manuscript work. No title, claims, references, numbering or paper figures were edited.', '',
      f'Pipeline verification: {len(cases)-failed} passed, {failed} failed/errored. '
      'This includes coordinated two-module contracts, rollback of every file on failed checks, stale-digest rejection, and JavaScript syntax/runtime checks.', '',
      f'Ordinary startup contract: {sum(r["passed"] for r in startup)}/{len(startup)} recorded baseline/finished synthetic configurations pass with the Flask server mocked. '
      'This executes initialization and checks the server call without opening a network server.', '',
      '## Five-model comparison', '',
      'The cohort uses exact model identities, the same pinned application, compact context, review-1 library, A/B definitions and one repetition. '
      'Supplemental Gemini 3.6 Flash and local Qwen 0.5B candidates were selected based on availability checks after hosted-service failures and quota exhaustion. All attempted candidates remain visible; the target is at least five completed pairs. '
      'Hosted and local inference have different resource and timeout constraints. Elapsed times include service delays, local queues and host pauses and are not normalized model-speed comparisons. These results describe this free cohort, not the paper’s original models. '
      'The small Qwen pair uses a declared 1024-token output limit after its original 8192-token run repeatedly timed out; other models use 8192. Both arms of each pair use the same limit. Effects are conditional on these budgets; this is not a model ranking under equal resources. '
      'A removes neither component; B removes both guidance and examples, so A−B is their joint effect. Earlier factorial runs isolate them separately.', '',
      '| Model | Reply cap | A progress/status | A alerts absent | B progress/status | B alerts absent | A−B (pp) |',
      '|---|---:|---|---:|---|---:|---:|']
    for pair in pairs:
        a, b = pair['A'], pair['B']
        lines.append(f"| {pair['model']} | {a['max_tokens'] or b['max_tokens'] or 'pending'} | {a['processed']}/{a['eligible'] or 29}; {a['status']} | {a['resolved'] if a['resolved'] is not None else 'unavailable'} | {b['processed']}/{b['eligible'] or 29}; {b['status']} | {b['resolved'] if b['resolved'] is not None else 'unavailable'} | {pair['A_minus_B_pp'] if pair['complete'] else 'unavailable'} |")
    effects = [p['A_minus_B_pp'] for p in pairs if p['complete']]
    lines += ['', f'Completed paired models: {len(effects)} of {len(MODELS)} attempted; target at least five. ' + (f'Observed joint-effect range: {min(effects):+.2f} to {max(effects):+.2f} percentage points.' if effects else 'No full paired range is available.'), '',
      'A partial run has no overall fix rate. Service failures are recorded as infrastructure interruptions, not rejected patches or completed results.', '',
      '## External applications', '',
      'PyGoat has 62 baseline CodeQL findings across 25 affected files; VAmPI has three findings. Separate clones preserve the pinned public inputs. '
      'All-findings runs are distinguished from the earlier two-finding cross-file pilot. Normal HTTP regression checks run in dedicated environments and isolated databases.', '',
      '| Run | Progress/status | Alerts absent | New alerts | Changed files |', '|---|---|---:|---:|---:|']
    for r in rows:
        if r['dataset'] != 'synthetic':
            lines.append(f"| {r['run']} | {r['processed']}/{r['eligible'] or ('62' if r['dataset']=='pygoat' else '3')}; {r['status']} | {r['resolved'] if r['resolved'] is not None else 'unavailable'} | {r['new_findings'] if r['new_findings'] is not None else 'unavailable'} | {r['files_changed'] if r['files_changed'] is not None else 'pending'} |")
    lines += ['', f'Completed post-repair application runtime checks recorded: {len(runtime)}. '
              'See external-runtime-summary.json for individual observations and infrastructure failures. '
              'Baseline PyGoat and VAmPI each pass nine normal-use checks. '
              'These ordinary checks alone are not security measurements. The expanded follow-up separately records authenticated targeted checks and a fixed-route passive ZAP profile.', '',
      '## Multi-file, production and language scope', '',
      'The coordinated edit API accepts digest-bound Python and JavaScript fragments, checks all source syntax before writing, '
      'and requires project checks after all edits. Failed validation restores all pre-edit bytes. This is process rollback, not crash-atomic filesystem persistence.', '',
      '| Production pilot | Applied and passed normal checks | Changed source lines | Security resolution |', '|---|---|---:|---|']
    for name, r in production:
        lines.append(f"| {name} | {r['accepted']} | {r['changed_lines']} | {r['security_resolution']} |")
    if multifile:
        lines += ['', f"Generated two-module fixture: accepted={multifile['accepted']}; {len(multifile['files'])} files changed in one coordinated proposal. "
                  'Four round trips, four output-format checks and one invalid-version check passed. The exact prompt, response, original fragments and proposed edits are saved in multifile-pilot. '
                  'This is an explicitly synthetic contract-migration pilot, not a production vulnerability repair rate.']
    if upstream:
        lines += ['', 'Corrected upstream ordinary unit checks:', '',
                  '| Library / state | Collected | Failed | Skipped |', '|---|---:|---:|---:|']
        for r in upstream:
            lines.append(f"| {r['dataset']} / {r['state']} | {r['tests']} | {r['failed']} | {r.get('skipped',0)} |")
        lines += ['', 'The original urllib3 test expects Authorization to be the only default removed header. '
                  'Its sole new failure is the deliberate addition of Cookie required by the maintainer advisory; the separate eight API/configuration checks verify that policy and preserved custom settings. '
                  'Eighteen timezone cases are skipped by the upstream fixture on Windows. '
                  'The first harness trial omitted the timezone fixture and used an asynchronous legacy JavaScript loader; its failures are retained as invalid harness observations. '
                  'The corrected baseline and patched minimist runs each pass 127 assertions. Prototype reproducer tests remain outside this ordinary unit profile.']
    lines += ['', 'The first minimist application rejected a CRLF-normalized fragment; that failure is retained. '
      'The second attempt preserved exact file bytes. These one-attempt model pilots cover real production source, '
      'but configuration/API checks do not establish production vulnerability fix rates or language-wide generalisation. '
      'The coordinated multi-file contract is a synthetic fixture; the production pilot changes each touch one file.', '',
      'Production sources: [urllib3 maintainer advisory](https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f) '
      'and [minimist advisory](https://github.com/advisories/GHSA-xvch-5gv4-984h). Input commits, source hashes, exact prompts, model responses and patches are saved with each pilot.', '',
      '## Guidance checks and original provenance', '']
    for r in vet:
        lines.append(f"- {r['version']}: {r['passing_entries']}/{len(r['entries'])} entries pass bounded automated checks.")
    lines += ['', 'The new revision enables the CSRF extension and handles invalid numeric input; it also makes several size bounds and context assumptions explicit. '
      'The measured cohort uses frozen review-1. Adoption defaults select review-2, whose security performance remains unmeasured. '
      'The 18/18 result covers those documented checks, not all possible application contexts. A separate Gemini model critique is saved in independent-model-review; '
      'its suggestions were not automatically adopted. Some suggestions require stronger application-specific validation than the critique describes.', '',
      'Original Git authorship and prompt-file histories are recorded in guidance-provenance.json. '
      'The public pipeline repository has no PR or issue records in the inspected snapshot; public application PR metadata is preserved separately in public-review-records.json. '
      'No original reviewer identities, qualifications or signoffs were established. Commit authorship is not evidence of expert vetting. '
      'There is no independent human expert signoff for either revision.', '',
      '## Deferred and unestablished work', '',
      '- Manuscript revisions are deferred at the user’s request.',
      '- Missing or interrupted experiment cells remain unavailable; the tables above are generated from saved observations.',
      '- Exhaustive active DAST coverage, language-wide generalisation, and original expert-review provenance remain unestablished. The follow-up provides bounded production performance and three proposals per selected defect.', '',
      'The Daybreak message reported by the user is a ChatGPT cybersecurity access safeguard. No attempt was made to grant that access or route around blocked content. '
      'The historical pilot checks above used normal behavior only; the follow-up adds fixture-based security assertions in isolated local environments.', '']
    (OUT / 'CODE_REVIEW_RESPONSE.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'paired_models_complete': len(effects), 'pipeline_checks_passed': len(cases)-failed,
                      'external_runtime_runs': len(runtime)}))


if __name__ == '__main__':
    main()
