"""Generate review tables from recorded observations, never planned outcomes."""
import ast
from collections import Counter
import csv
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from review.runner import ROOT, contexts, dump, digest, checked, command, taint_paths, file_count
from review.zap_summary import groups as zap_groups, compare as compare_zap
from factorial_prompts import ENTRIES
from review.project_paths import synthetic_repo

out = ROOT / 'review_results'
datasets = [('synthetic', synthetic_repo()),
            ('pygoat',ROOT/'benchmarks/pygoat'),('vampi',ROOT/'benchmarks/vampi')]
baseline_rows = []
for name, repo in datasets:
    sarif = out / f'baseline-{name}/scan.sarif'
    if not sarif.exists(): continue
    saved = out/f'baseline-{name}/dataset-manifest.json'
    if saved.exists():
        prior=json.loads(saved.read_text(encoding='utf-8'))
        if prior['sarif_sha256']==digest(sarif) and (not (repo/'.git').exists() or
                prior['source_commit']!=checked(['git','rev-parse','HEAD'],repo)):
            baseline_rows.append(prior)
            continue
    if not (repo/'.git').exists():
        raise RuntimeError(f'Clone the pinned {name} source or supply its recorded dataset manifest')
    findings = contexts(repo, sarif)
    cwes = Counter(f['sast']['cwe'] for f in findings)
    covered = sum(count for cwe,count in cwes.items() if cwe and int(cwe.split('-')[-1]) in ENTRIES)
    cross_file = sum(any(file_count(p)>1 for p in taint_paths(f)) for f in findings)
    row = {'dataset':name,'source_url':checked(['git','remote','get-url','origin'],repo),
           'source_commit':checked(['git','rev-parse','HEAD'],repo),
           'findings':len(findings),'affected_files':len({f['sast']['location']['file_path'] for f in findings}),
           'cwe_classes':len(cwes),'cwes':dict(cwes),'library_covered_findings':covered,
           'cross_file_taint_findings':cross_file, 'sarif_sha256':digest(sarif)}
    baseline_rows.append(row)
    dump(out/f'baseline-{name}/dataset-manifest.json',row)
    dump(out/f'baseline-{name}/contexts.json',findings)
dump(out/'baseline-summary.json',baseline_rows)

runs = []
for path in sorted(out.glob('*/manifest.json')):
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if 'condition' not in manifest: continue
    results_path = path.parent/'results.json'
    results = json.loads(results_path.read_text(encoding='utf-8')) if results_path.exists() else []
    earlier = [json.loads(p.read_text(encoding='utf-8')) for p in path.parent.glob('interrupted-finding-*.json')]
    counts = Counter()
    rejects = Counter()
    api_tokens, api_seconds, attempts = 0, 0, 0
    for result in results + earlier:
        counts.update(result.get('application_counts') or {})
        for attempt in result.get('attempts', []):
            attempts += 1
            api_seconds += attempt.get('duration_seconds', 0)
            api_tokens += (attempt.get('response') or {}).get('usage', {}).get('total_tokens', 0)
            for gate,value in (attempt.get('validation') or {}).items():
                if isinstance(value,dict) and value.get('passed') is False:
                    rejects[gate]+=1
    scan = manifest.get('sast') or {}
    completed = manifest['status'] == 'complete' and manifest.get('selected_findings') == manifest.get('eligible_findings')
    row = {'run':path.parent.name,'model':manifest['model'],'condition':manifest['condition'],
           'thinking':manifest.get('thinking_level','provider default'), 'status':manifest['status'],
           'processed':len(results),'eligible':manifest['eligible_findings'],
           'accepted':sum(r.get('accepted',False) for r in results),
           'accepted_after_retry':sum(bool(r.get('accepted')) and len(r.get('attempts',[]))>1 for r in results),
           'resolved':scan.get('resolved_findings') if completed else None,
           'new_findings':scan.get('new_findings') if completed else None,
           'checkpoint_absent_alerts':scan.get('resolved_findings') if not completed else None,
           'security_fix_rate':scan.get('resolution_rate') if completed else None,
           'attempts':attempts,'tokens_reported':api_tokens,'generation_seconds':round(api_seconds,2),
           'repair_loop_seconds_total':round(sum(h.get('previous_elapsed_seconds') or 0 for h in manifest.get('resume_history',[]))+(manifest.get('elapsed_seconds') or 0),2) if manifest['status']!='running' else None,
           'lines_added':sum(r.get('lines_added',0) for r in results),
           'lines_removed':sum(r.get('lines_removed',0) for r in results),
           'post_test_failures':len(manifest['post_tests']['failures']) if manifest.get('post_tests',{}).get('failures') is not None else None,
           'application_counts':dict(counts),'validation_rejections':dict(rejects),
           'post_tests':manifest.get('post_tests',{}).get('status','pending')}
    runs.append(row)
    if manifest['status'] != 'running' and (path.parent/'source/.git').exists():
        patch = command(['git','diff','--binary','HEAD','--','*.py'],path.parent/'source')
        if not patch.returncode and patch.stdout:
            (path.parent/'net.patch').write_text(patch.stdout,encoding='utf-8',newline='')
dump(out/'run-summary.json',runs)
for filename, rows in [('baseline-summary.csv',baseline_rows),('run-summary.csv',runs)]:
    if not rows: continue
    with (out/filename).open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)

verification = out/'verification.xml'
test_cases = list(ET.parse(verification).iter('testcase')) if verification.exists() else []
test_errors = sum(c.find('failure') is not None or c.find('error') is not None for c in test_cases)
lines = ['# Implementation review and measured results', '',
    'For the continued code-only response and latest free-model/external observations, see `continuation/results/CODE_REVIEW_RESPONSE.md`. '
    'The user deferred manuscript changes. The earlier factorial and DAST series below remain separate from that continuation.', '',
    'The local code changes and the experiments below address execution-related comments in Comments Received.docx. '
    'The work is incomplete until the pending comparisons and runtime evaluations are measured. '
    'No result here should be substituted for the original paper’s five-model measurements.', '',
    f'Pipeline verification: {len(test_cases)-test_errors} checks passed; {test_errors} failed or errored. '
    'The unchanged synthetic app passed 68 selected functional tests before the repair attempts.', '',
    '## Fresh security baselines', '',
    '| Dataset | CodeQL findings | Affected files | CWE classes | Findings covered by the 18-entry library | Cross-file taint findings |',
    '|---|---:|---:|---:|---:|---:|']
for r in baseline_rows:
    lines.append(f"| {r['dataset']} | {r['findings']} | {r['affected_files']} | {r['cwe_classes']} | {r['library_covered_findings']} | {r['cross_file_taint_findings']} |")
lines += ['', 'CodeQL CLI 2.27.4 with Python queries 1.9.0 and the security-extended suite produced these new scans. '
          'PyGoat and VAmPI are independently maintained vulnerable training applications. '
          'They broaden source and framework coverage but do not establish performance on production CVEs. '
          'Repository-wide scans may cover several independently deployed lab apps; the file count is not a count of multi-file repair transactions.', '',
          '## Repair observations', '',
          '| Run | Status | Processed | Accepted patches | Resolved by re-scan | New findings | Post tests |',
          '|---|---|---:|---:|---:|---:|---|']
for r in runs:
    tests=r['post_tests']+ (f" ({r['post_test_failures']} failures)" if r['post_test_failures'] else '')
    lines.append(f"| {r['run']} | {r['status']} | {r['processed']}/{r['eligible']} | {r['accepted']} | {r['resolved'] if r['resolved'] is not None else 'unavailable'} | {r['new_findings'] if r['new_findings'] is not None else 'unavailable'} | {tests} |")
synthetic_a=next((r for r in runs if r['run']=='gemma26-A-synthetic-v3-r1' and r['resolved'] is not None),None)
synthetic_simple=next((r for r in runs if r['run']=='gemma-4-26b-a4b-it-simple-synthetic-matched-r1' and r['resolved'] is not None),None)
if synthetic_a and synthetic_simple:
    lines += ['', f"On the original app, the same-model simpler run removed {synthetic_simple['resolved']} CodeQL findings versus "
             f"{synthetic_a['resolved']} for A. The simpler run changed {synthetic_simple['lines_added']+synthetic_simple['lines_removed']} "
             f"lines across accepted patches and had {synthetic_simple['post_test_failures']} failing assertions; "
             f"A changed {synthetic_a['lines_added']+synthetic_a['lines_removed']} lines and had {synthetic_a['post_test_failures']} failing assertions. "
             'This comparison does not establish that either workflow is preferable across models or projects.']
lines += ['', 'Acceptance means that the configured inline gates passed. Security resolution is calculated only for a completed full-selection run with a fresh re-scan. '
          'Interrupted requests are access failures, not measurements of model patch quality. '
          'Default-thinking pilots and explicitly minimal-thinking runs are separate cohorts. '
          'A run without project tests supplies static evidence only. Changes to regexes or API input handling still require behavioral review.', '',
          '## Reviewer concerns', '',
          '| Concern | Implementation and evidence | Remaining work |',
          '|---|---|---|',
          '| R1 external validity; R2 question 2; R3 evaluation breadth | Separate PyGoat and VAmPI clones; pinned commits, fresh SARIF, source contexts, and library coverage counts | Complete matched repair runs, project regression suites, authenticated runtime checks, and production-CVE evaluation before broad claims |',
          '| R1 single-model Run B | Explicit seven-condition experiment plan retains all five original model identifiers; new free models are recorded separately | Complete B and A for each model in the chosen cohort; original five-model access is not configured |',
          '| R2 question 5 confounded guidance/examples ablation | One scaffold with independently controlled rules and examples; tested in initial and retry prompts | Execute all four guidance/example cells with matched settings and report per-model differences; no guidance contribution is inferred from missing cells |',
          '| R1 marginal validation benefit | Per-attempt gates, rollback, token use, time and churn; C disables gates with one attempt; A_strict separates blocking tests | Complete A/C matched comparisons; report security resolution, patch scope and regressions separately |',
          '| R2 questions 3 and 4 guidance and expert examples | Full new 18-entry library with sources and one before/after pair per CWE; original library retained in new_prompts.py | Independent expert vetting and original-author provenance remain unknown; no expert-review claim is made |',
          '| R2 question 6 adoption requirements | README gives credentials, scanners, source pins, test policies, local publication policy and runtime limits | Project-specific setup, authorization rules, authentication profiles, regression contracts and deployment checks |',
          '| R2 question 7 patch fallback counts | Each real application records ast_name, ast_line_fallback, verified_line or rejected, with successes/failures; run-summary.json aggregates observed counts | Historical fallback frequencies cannot be reconstructed without original attempt logs; approximate fallback is intentionally absent in this revision |',
          '| R2 question 9 full prompt | Every attempted finding saves prompt.json and attempt files; prompt-example.md exports a complete readable example | Any paper appendix must identify the revision and matching generation settings |',
          '| R3 external baseline | A simpler one-shot, shorter-context condition is implemented using the same model, source and re-scan oracle | Complete matched simple/A runs; a modern independent coding-agent baseline remains unevaluated |',
          '| R3 clean replication and released-method mismatch | Corrected enabled-gate configuration, local-only runner, pinned inputs, environment snapshot, raw outputs, CSV and JSON tables | Original A/B/C results are not claimed reproduced; completed new comparisons are needed |',
          '| Manuscript-only issues | Title terminology, RQ ordering, citations, claims, grammar and figure sizing identified as outside this implementation task | The paper was not supplied and has not been edited |', '',
          '## Patch application counts', '',
          '| Run | Attempts to apply | Applied | Failed to apply | AST name | AST line fallback | Verified line |',
          '|---|---:|---:|---:|---:|---:|---:|']
for r in runs:
    c=r['application_counts']
    lines.append(f"| {r['run']} | {c.get('attempts',0)} | {c.get('success',0)} | {c.get('failures',0)} | {c.get('ast_name',0)} | {c.get('ast_line_fallback',0)} | {c.get('verified_line',0)} |")
checkpoints=[r for r in runs if r['checkpoint_absent_alerts'] is not None and r['accepted']]
if checkpoints:
    lines += ['', 'The following partial re-scans describe checkpoint source states. They are excluded from full-run rates:', '']
    for r in checkpoints:
        lines.append(f"- {r['run']}: {r['checkpoint_absent_alerts']} baseline alerts absent after {r['processed']}/{r['eligible']} findings were processed.")
lines += ['', 'An API attempt that produces no candidate is not an application attempt. A syntactically applied candidate may later be rejected by a gate and rolled back. These are distinct counts.', '',
          '## Dynamic scan status', '']
for path in sorted(out.glob('dast-*/status.json')):
    status=json.loads(path.read_text())
    report=path.parent/'scan.json'
    count=f'; {len(zap_groups(report))} unique alert groups' if status['status']=='complete' and report.exists() else ''
    lines.append(f"- {path.parent.name}: {status['status']}{count}. {status.get('limits','')}")
zap_base=out/'dast-baseline-synthetic-v3/scan.json'
zap_post=out/'dast-post-synthetic-A/scan.json'
if zap_base.exists() and zap_post.exists():
    comparison=compare_zap(zap_base,zap_post)
    dump(out/'dast-comparison.json',comparison)
    lines += ['',f"Matched local scan profile, using the original app's seven-patch checkpoint: {comparison['resolved_groups']} baseline alert groups absent in the post-scan, "
              f"{comparison['remaining_baseline_groups']} retained, {comparison['new_groups']} new. "
              'A missing group may also reflect changed crawl reachability; this is an alert-group comparison, not a finding-level exploitability guarantee.']
full_post=out/'dast-post-synthetic-full-A/scan.json'
if zap_base.exists() and full_post.exists():
    comparison=compare_zap(zap_base,full_post)
    dump(out/'dast-full-A-comparison.json',comparison)
    lines += ['',f"After the completed guided run: {comparison['resolved_groups']} baseline alert groups absent, "
              f"{comparison['remaining_baseline_groups']} retained, and {comparison['new_groups']} new under the same profile."]
simple_post=out/'dast-post-synthetic-simple/scan.json'
if zap_base.exists() and simple_post.exists():
    comparison=compare_zap(zap_base,simple_post)
    dump(out/'dast-simple-comparison.json',comparison)
    lines += ['',f"After the completed simpler run: {comparison['resolved_groups']} baseline alert groups absent, "
              f"{comparison['remaining_baseline_groups']} retained, and {comparison['new_groups']} new under the same profile."]
lines += ['', 'The bounded ZAP profile is unauthenticated. Scanner alert groups and SAST findings are separate units.', '',
          '## Bounded external runtime check', '',
          'The VAmPI regex probe extracts the actual regex constants from the baseline and patched sources. It measures a bounded near-miss input and checks whether several email strings match, without importing or running the service. '
          'The generated `vampi-regex-check.csv` records five-repeat medians and match results. Both 26B variants changed acceptance of `alice@localhost` in one branch, which illustrates why static resolution alone does not establish preserved behaviour. '
          'This is a regex-level check, not a full HTTP, authentication, or regression test.', '',
          '## Evidence files', '',
          '- `baseline-summary.json` and `.csv`: current scanner baselines and source commits.',
          '- `run-summary.json` and `.csv`: only observed attempts and completed scanner results.',
          '- `experiment-plan.json`: planned original five-model cells, explicitly not run.',
          '- `paired-effects.json`: comparisons computed only from completed matched conditions.',
          '- `verification.xml`: pipeline regression checks.',
          '- `environment-freeze.txt`: exact installed package versions.',
          '- Each run folder: source clone, contexts, full prompts, responses, diffs, test records, and re-scan reports. Finished or interrupted runs with changes also have a net.patch against their exact source commit.',
          '- Each baseline folder: fresh SARIF, CodeQL logs and source identity.', '',
          'No credential is needed to inspect these records. Do not publish vulnerable app runtime data or API credentials with the package.']
effects=out/'paired-effects.json'
if effects.exists():
    observed=[r for r in json.loads(effects.read_text(encoding='utf-8')) if any(r[k] is not None for k in
              ('guidance_plus_examples_pp','isolated_guidance_effect_pp','guidance_given_examples_pp',
               'examples_given_guidance_pp','A_minus_C_security_pp'))]
    if observed:
        lines += ['', '## Completed paired effects', '', 'Values are percentage-point changes in the CodeQL resolution rate within a matched run. '
                  'One repetition provides a descriptive result; missing cells stay unavailable.', '',
                  '| Model | A minus B | Guidance with examples fixed | Examples with guidance fixed | Factorial guidance | Factorial examples | Interaction | A minus C |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|']
        for r in observed:
            values=[r[k] for k in ('guidance_plus_examples_pp','guidance_given_examples_pp','examples_given_guidance_pp',
                                    'isolated_guidance_effect_pp','isolated_example_effect_pp',
                                    'interaction_pp','A_minus_C_security_pp')]
            lines.append('| '+r['model']+' | '+' | '.join(f'{v:+.2f}' if v is not None else 'unavailable' for v in values)+' |')
(out/'REVIEW_RESPONSE.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')

examples=sorted(out.glob('gemma*/finding-*/prompt.json'))
if examples:
    p=examples[0]; data=json.loads(p.read_text())
    (out/'prompt-example.md').write_text('# Complete prompt example\n\nSource record: '+str(p.relative_to(ROOT))
        +'\n\n## System prompt\n\n'+data['system']+'\n\n## User prompt\n\n'+data['user']+'\n',encoding='utf-8')
print('Generated baseline tables, run tables, prompt appendix and REVIEW_RESPONSE.md')
