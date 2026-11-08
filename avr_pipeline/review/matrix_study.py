"""Plan or execute the frozen equal-budget study; plans never count as results."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from threading import Lock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import CONDITIONS, dump, implementation_hashes, LLMClient, checked
from review.project_paths import synthetic_repo, verify_input

DATASETS = ('synthetic', 'pygoat', 'vampi', 'flask-webgoat')
FACTORIAL = ('A', 'B', 'no_guidance', 'no_examples', 'C', 'simple', 'A_strict')


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', nargs='+', choices=DATASETS, required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--model', nargs='+')
    group.add_argument('--cohort', help='JSON list of {model, provider}; no paid fallback')
    p.add_argument('--conditions', nargs='+', choices=list(CONDITIONS), default=list(FACTORIAL))
    reps = p.add_mutually_exclusive_group()
    reps.add_argument('--repetitions', type=int)
    reps.add_argument('--repetition-ids', nargs='+', type=int)
    p.add_argument('--jobs', type=int, choices=(1, 2), default=1)
    p.add_argument('--tag', required=True)
    p.add_argument('--provider', choices=('gemini', 'openrouter', 'ollama', 'local'), default='gemini')
    p.add_argument('--max-tokens', type=int, default=8192)
    p.add_argument('--context-profile', choices=('full', 'compact'), default='compact')
    p.add_argument('--guidance-library', default=str(ROOT / 'llm/guidance_library.review-2.json'))
    p.add_argument('--results', type=Path, default=ROOT / 'review_results')
    p.add_argument('--execute', action='store_true', help='Otherwise write the plan only')
    p.add_argument('--resume-interrupted', action='store_true')
    p.add_argument('--limit', type=int, help='Pilot only; excluded from full-study effects')
    p.add_argument('--codeql')
    p.add_argument('--requests-per-minute',type=int,default=12)
    p.add_argument('--validation-environments', type=Path, help='Owner-supplied JSON mapping dataset to its target interpreter')
    return p


def build_plan(args):
    if not re.fullmatch(r'[A-Za-z0-9-]+', args.tag):
        raise ValueError('Use an alphanumeric tag with optional hyphens')
    reps = args.repetition_ids or (list(range(1, args.repetitions + 1)) if args.repetitions is not None
                                  else [int(args.tag[1:])] if re.fullmatch(r'r[1-9][0-9]*', args.tag)
                                  else [1, 2, 3])
    if not reps or min(reps) < 1 or len(set(reps)) != len(reps) or args.max_tokens < 1 or args.requests_per_minute < 1:
        raise ValueError('Repetitions and reply budget must be positive and unique')
    cohort = json.loads(Path(args.cohort).read_text(encoding='utf-8')) if args.cohort else [
        {'model': m, 'provider': args.provider} for m in args.model]
    if not cohort or len({(m['provider'], m['model']) for m in cohort}) != len(cohort):
        raise ValueError('Cohort must contain unique model/provider pairs')
    for m in cohort:
        if m['provider'] not in ('gemini', 'openrouter', 'ollama', 'local') or not re.fullmatch(r'[A-Za-z0-9./:_-]+', m['model']):
            raise ValueError('Invalid model/provider')
        if m['provider'] == 'openrouter' and not m['model'].endswith(':free'):
            raise ValueError('Only explicitly free OpenRouter routes are permitted')
    library = Path(args.guidance_library).read_bytes()
    if json.loads(library)['version'] != 'review-2':
        raise ValueError('New study runs require review-2 guidance')
    frozen = json.loads((ROOT / 'review/study-protocol.json').read_text())
    library_hash = hashlib.sha256(library).hexdigest()
    if library_hash != frozen['library_sha256']:
        raise ValueError('Guidance differs from frozen protocol')
    if hashlib.sha256((ROOT/'review/test-policy.json').read_bytes()).hexdigest() != frozen['test_policy_sha256']:
        raise ValueError('Test classification differs from frozen protocol')
    if args.limit is not None and args.limit < 1:
        raise ValueError('Pilot limit must be positive')
    cells = []
    for d in args.dataset:
        repo = synthetic_repo() if d == 'synthetic' else ROOT / 'benchmarks' / d
        baseline = ROOT / 'review_results' / f'baseline-{d}' / 'scan.sarif'
        for r in reps:
            for c in args.conditions:
                for m in cohort:
                    stem = re.sub(r'[^A-Za-z0-9.-]', '-', m['model'])
                    name = f'{stem}-{c}-{d}-{args.tag}-r{r}'
                    cells.append(dict(m, dataset=d, condition=c, repetition=r, run=name,
                                      repo=str(repo), sarif=str(baseline), status='not_run'))
    protocol = {'schema': 2, 'library_version': 'review-2', 'library_sha256': library_hash,
                'implementation_sha256':implementation_hashes(),
                'validation_environments':json.loads(args.validation_environments.read_text()) if args.validation_environments else {},
                'max_tokens': args.max_tokens, 'context_profile': args.context_profile,
                'requests_per_minute':args.requests_per_minute,
                'temperature': 0.1, 'spending': 'free/local only', 'limit': args.limit,
                'repetitions': reps, 'conditions': {c: CONDITIONS[c] for c in args.conditions},
                'measurement': frozen['measurement'], 'cells': cells}
    protocol['plan_sha256'] = hashlib.sha256(json.dumps(protocol, sort_keys=True).encode()).hexdigest()
    return protocol


class AccessState:
    def __init__(self):
        self.lock, self.blocked, self.failures = Lock(), {}, {}

    def reason(self, cell):
        with self.lock:
            return self.blocked.get((cell['provider'],cell['model']))

    def observe(self, cell, errors):
        key = (cell['provider'],cell['model'])
        text = '\n'.join(errors).lower()
        with self.lock:
            if 'requests per day' in text or 'generaterequestsperday' in text:
                self.blocked[key] = 'daily_quota'
            elif any(x in text for x in ('http 500','http 503','api error 500','api error 503','local api error','ollama api error')):
                self.failures[key] = self.failures.get(key,0)+1
                if self.failures[key] >= 3:
                    self.blocked[key] = 'provider_unavailable'
            elif not errors:
                self.failures[key] = 0


def execute(cell, args, protocol, access=None):
    reason = access.reason(cell) if access else None
    if reason:
        return dict(cell,status='deferred_'+reason)
    out = args.results / cell['run']
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / 'manifest.json'
    resume = False
    if manifest_path.exists():
        old = json.loads(manifest_path.read_text())
        if old.get('implementation_sha256') != protocol['implementation_sha256']:
            raise ValueError('Implementation changed; select a fresh study tag instead of reusing old runs')
        for key, value in [('max_tokens', args.max_tokens), ('library_sha256', protocol['library_sha256']),
                           ('context_profile', args.context_profile), ('repetition', cell['repetition'])]:
            if old.get(key) != value:
                raise ValueError(f'Existing run has a different {key}: {out}')
        if old.get('status') in ('running', 'complete'):
            return dict(cell, status='already_' + old['status'])
        if not args.resume_interrupted:
            return dict(cell, status='interrupted_requires_explicit_resume')
        resume = True
    cli = [sys.executable, str(ROOT / 'review/runner.py'), 'run', '--repo', cell['repo'],
           '--sarif', cell['sarif'], '--out', str(out), '--model', cell['model'],
           '--provider', cell['provider'], '--condition', cell['condition'],
           '--repetition', str(cell['repetition']), '--max-tokens', str(args.max_tokens),
           '--guidance-library', str(Path(args.guidance_library).resolve()),
           '--context-profile', args.context_profile, '--rescan']
    if args.codeql:
        cli += ['--codeql', args.codeql]
    if cell['dataset'] in protocol['validation_environments']:
        cli += ['--validation-python',protocol['validation_environments'][cell['dataset']]]
    if args.limit:
        cli += ['--limit', str(args.limit)]
    if resume:
        cli.append('--resume')
    print('Starting ' + cell['run'], flush=True)
    with (out / 'runner.log').open('a', encoding='utf-8') as log:
        env = dict(os.environ,AVR_REQUEST_BUDGET_PER_MINUTE=str(args.requests_per_minute))
        result = subprocess.run(cli, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,env=env)
    record = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if access:
        result_path = out/'results.json'
        records = json.loads(result_path.read_text()) if result_path.exists() else []
        errors = [a.get('error','') for r in records for a in r.get('attempts',[]) if a.get('infrastructure_error')]
        access.observe(cell,errors)
    status = dict(cell, status=record.get('status', 'runner_failed'), returncode=result.returncode)
    print(json.dumps({k: status[k] for k in ('run', 'status', 'returncode')}), flush=True)
    return status


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    try:
        protocol = build_plan(args)
    except (ValueError, KeyError) as exc:
        p.error(str(exc))
    args.results.mkdir(parents=True, exist_ok=True)
    target = args.results / f'study-{args.tag}.json'
    if target.exists() and json.loads(target.read_text()).get('executed'):
        target = args.results / f'study-{args.tag}-plan.json'
    dump(target, protocol)
    print(f"Planned {len(protocol['cells'])} cells; repetitions {protocol['repetitions']}; equal cap {args.max_tokens}")
    if not args.execute:
        print('Plan only. Add --execute to run. No outcomes were generated.')
        return
    for provider,model in {(c['provider'],c['model']) for c in protocol['cells']}:
        LLMClient(provider,model,max_tokens=args.max_tokens)  # Configuration only; no request.
    for cell in {c['dataset']:c for c in protocol['cells']}.values():
        if not Path(cell['sarif']).is_file() or not (Path(cell['repo']) / '.git').exists():
            p.error(f"Prepare pinned input and baseline first: {cell['dataset']}")
        try:
            verify_input(cell['repo'],cell['sarif'],checked,cell['dataset'])
        except ValueError as exc:
            p.error(str(exc))
    access = AccessState()
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        protocol['cells'] = list(executor.map(lambda c: execute(c, args, protocol,access), protocol['cells']))
    protocol['executed'] = True
    dump(target, protocol)


if __name__ == '__main__':
    main()
