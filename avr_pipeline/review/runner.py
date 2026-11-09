"""Local-only, reproducible repair experiments. No push, PR, or remote writes.

Run from the repository root: python review/runner.py --help
"""
import argparse
import ast
from collections import Counter
from copy import deepcopy
import csv
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'llm'), str(ROOT / 'context_builder')]
from parsers.ast_utils import function_at, locate, boundaries
from codePatcherAST import CodePatcher
from factorial_prompts import PromptBuilder, SYSTEM_PROMPT, LIBRARY
from minimality_validator import validate_fix_minimality
from llm_client import LLMClient, GenerationLimitError, ModelOutputError
from egress_guard import sanitise
sys.path.insert(0, str(ROOT))
from review.project_paths import tool_path, query_pack_root, verify_input
from review.outcomes import export_run
from review.target_environment import target_python, describe as describe_environment, lint_options
from review.validation_health import ValidatorInfrastructureError, require_lint_health

CONDITIONS = {
    'A': dict(guidance=True, examples=True, gates=True, attempts=3, tests='monitor'),
    'B': dict(guidance=False, examples=False, gates=True, attempts=3, tests='monitor'),
    'C': dict(guidance=True, examples=True, gates=False, attempts=1, tests='monitor'),
    'no_guidance': dict(guidance=False, examples=True, gates=True, attempts=3, tests='monitor'),
    'no_examples': dict(guidance=True, examples=False, gates=True, attempts=3, tests='monitor'),
    'simple': dict(guidance=False, examples=False, gates=False, attempts=1, tests='monitor', simple=True),
    'A_strict': dict(guidance=True, examples=True, gates=True, attempts=3, tests='block')}
ORIGINAL_MODELS = ['qwen/qwen3.5-flash-02-23', 'moonshotai/kimi-k2.5',
                   'minimax/minimax-m2.5', 'deepseek/deepseek-v3.2', 'z-ai/glm-5']


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.tmp')
    pending.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    pending.replace(path)


def command(args, cwd=None, timeout=600):
    child_env = {k:v for k,v in os.environ.items()
                 if not re.search(r'(api.?key|token|secret|password|credential|access.?key)', k, re.I)}
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=timeout, env=child_env)


def checked(args, cwd=None, timeout=600):
    result = command(args, cwd, timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}): {args[0]}\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}')
    return result.stdout.strip()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def implementation_hashes():
    paths = [Path(__file__), ROOT/'llm/llm_client.py', ROOT/'llm/review_patcher.py',
             ROOT/'llm/factorial_prompts.py', ROOT/'llm/minimality_validator.py',
             ROOT/'llm/egress_guard.py', ROOT/'llm/request_budget.py',
             ROOT/'context_builder/parsers/ast_utils.py', ROOT/'context_builder/parsers/code_fetcher.py',
             ROOT/'llm/codePatcherAST.py', ROOT/'review/outcomes.py', ROOT/'review/project_paths.py',
             ROOT/'review/external_security.py', ROOT/'review/behavioral/external_assertions.py',
             ROOT/'review/behavioral/conftest.py', ROOT/'review/target_environment.py',
             ROOT/'review/validation_health.py']
    return {str(p.relative_to(ROOT)):digest(p) for p in paths}


def scan(repo, out, codeql=None):
    repo, out = Path(repo).resolve(), Path(out).resolve()
    if out.is_relative_to(repo):
        raise ValueError('Scanner output must be outside the source tree')
    out.mkdir(parents=True, exist_ok=True)
    executable = codeql or tool_path('codeql')
    if not Path(executable).exists() and not shutil.which(executable):
        raise RuntimeError('CodeQL unavailable; cannot report SAST resolution')
    database = out / 'codeql-db'
    if database.is_symlink() or database.resolve().parent != out:
        raise ValueError('CodeQL database path must stay inside its run directory')
    env_path = os.environ.get('PATH', '')
    os.environ['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env_path
    try:
        steps = [
            [executable, 'database', 'create', database, '--language=python',
             f'--source-root={repo}', '--overwrite', '--threads=2', '--ram=2048'],
            [executable, 'database', 'analyze', database,
             'codeql/python-queries:codeql-suites/python-security-extended.qls',
             '--search-path=' + os.pathsep.join(str(p.parent) for p in query_pack_root().rglob('qlpack.yml')),
             '--format=sarif-latest', f'--output={out / "scan.sarif"}', '--threads=2', '--ram=2048']]
        for i, args in enumerate(steps):
            result = command(args, cwd=repo, timeout=1800)
            (out / f'codeql-{i}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
            if result.returncode:
                raise RuntimeError(f'CodeQL step {i} failed; see {out / f"codeql-{i}.log"}')
        dump(out / 'scan-provenance.json', {'tool': checked([executable, 'version', '--format=json']),
             'query_suite': 'python-security-extended', 'query_pack': 'codeql/python-queries@1.9.0',
             'repo': str(repo), 'sarif_sha256': digest(out / 'scan.sarif'), 'utc': datetime.now(timezone.utc).isoformat()})
    finally:
        os.environ['PATH'] = env_path
    return out / 'scan.sarif'


def source_path(uri):
    parsed = urlsplit(uri)
    if parsed.scheme or parsed.netloc:
        raise ValueError('Only repository-relative SARIF locations are supported')
    path = unquote(parsed.path)
    if Path(path).is_absolute() or '..' in Path(path).parts:
        raise ValueError('SARIF location escapes source root')
    return path.replace('\\', '/')


def contexts(repo, sarif, zap=None):
    """Bind target names once on the immutable baseline, across every SARIF run."""
    repo = Path(repo).resolve()
    data = json.loads(Path(sarif).read_text(encoding='utf-8-sig'))
    findings = []
    for run in data.get('runs', []):
        rules = {r['id']: r for tool in [run.get('tool', {}).get('driver', {})] + run.get('tool', {}).get('extensions', [])
                 for r in tool.get('rules', [])}
        for result in run.get('results', []):
            physical = result['locations'][0]['physicalLocation']
            path = source_path(physical['artifactLocation']['uri'])
            target = (repo / path).resolve()
            if not target.is_relative_to(repo):
                raise ValueError('SARIF source outside clone')
            line = physical['region']['startLine']
            source = target.read_text(encoding='utf-8')
            match = function_at(ast.parse(source), line)
            rule = rules.get(result['ruleId'], {})
            cwes = [t.rsplit('/', 1)[-1].upper() for t in rule.get('properties', {}).get('tags', []) if '/cwe/cwe-' in t.lower()]
            loc = {'file_path': path, 'start_line': line, 'end_line': physical['region'].get('endLine', line),
                   'function': match[0] if match else None}
            item = {'finding_number': f'FINDING {len(findings)+1:03d}',
                    'finding_id': f"{result['ruleId']}:{path}:{line}:{len(findings)}",
                    'sast': {'present': True, 'tool': 'codeql', 'rule_id': result['ruleId'],
                             'cwe': cwes[0] if cwes else '', 'all_cwes': cwes,
                             'description': result.get('message', {}).get('text', ''),
                             'location': loc, 'data_flow': result.get('codeFlows', [])},
                    'dast': {'present': False, 'reason': 'No endpoint-linked ZAP evidence supplied'},
                    'partial_fingerprints': result.get('partialFingerprints', {})}
            # Whole module statements get an exact baseline anchor, never a blind stale line edit.
            if not match:
                nodes = [n for n in ast.parse(source).body if n.lineno <= line <= n.end_lineno]
                if len(nodes) == 1:
                    node = nodes[0]
                    loc['start_line'], loc['end_line'] = node.lineno, node.end_lineno
                    item['module_snapshot'] = '\n'.join(source.splitlines()[node.lineno-1:node.end_lineno])
            findings.append(item)
    if zap:
        # CWE correlation is retained as a class-level hint only. It is not a
        # claim that a ZAP request demonstrates exploitability of this source finding.
        sites = json.loads(Path(zap).read_text(encoding='utf-8')).get('site', [])
        if isinstance(sites, dict):
            sites = [sites]
        alerts = [a for s in sites for a in s.get('alerts', [])]
        for item in findings:
            cwe = item['sast']['cwe']
            hints = [a for a in alerts if cwe and str(a.get('cweid', '')).lstrip('0') == cwe.split('-')[-1].lstrip('0')]
            if hints:
                item['dast'] = {'present': True, 'correlation': 'CWE class hint only; endpoint not proven', 'alerts': hints}
    return sorted(findings, key=lambda f: (f['sast']['location']['file_path'], -f['sast']['location']['start_line']))


def taint_paths(finding):
    paths = []
    for flow in finding['sast']['data_flow']:
        for thread in flow.get('threadFlows', []):
            steps = []
            for step in thread.get('locations', []):
                loc = step.get('location', {})
                physical = loc.get('physicalLocation', {})
                steps.append({'file':physical.get('artifactLocation', {}).get('uri', ''),
                              'line':physical.get('region', {}).get('startLine'),
                              'node':loc.get('message', {}).get('text', '')[:160]})
            if steps: paths.append(steps)
    return paths


def file_count(path):
    return len({step['file'] for step in path if step['file']})


def compact_context(finding):
    """Keep representative cross-file traces and their endpoints, with omission counts."""
    compact = deepcopy(finding)
    paths = sorted(taint_paths(finding), key=lambda p: (-file_count(p), len(p)))
    selected = [{'steps':p if len(p)<=36 else p[:18]+p[-18:], 'omitted_steps':max(0,len(p)-36)} for p in paths[:2]]
    compact['sast']['data_flow'] = {'profile':'compact','paths':selected,'omitted_paths':max(0,len(paths)-2)}
    if compact['dast'].get('alerts'):
        alerts = compact['dast']['alerts']
        compact['dast']['alerts'] = [{k:a.get(k) for k in ('pluginid','name','cweid','riskcode')}
             | {'instances':[{k:str(i.get(k,''))[:500] for k in ('uri','method','param','evidence')}
                             for i in (a.get('instances') or [])[:2]]} for a in alerts[:3]]
        compact['dast']['omitted_alerts'] = max(0,len(alerts)-3)
    return compact


def current(repo, finding):
    loc = finding['sast']['location']
    source = (repo / loc['file_path']).read_text(encoding='utf-8')
    if loc['function']:
        node = locate(ast.parse(source), loc['function'])
        start, end = boundaries(node)
        snippet = '\n'.join(source.splitlines()[start-1:end])
    else:
        snapshot = finding.get('module_snapshot')
        if not snapshot or source.count(snapshot) != 1:
            raise ValueError('Module anchor missing or ambiguous after previous patches')
        start = source[:source.index(snapshot)].count('\n') + 1
        end = start + len(snapshot.splitlines()) - 1
        snippet = snapshot
    return snippet, {'function_name': loc['function'], 'file_path': loc['file_path'],
                     'start_line': start, 'end_line': end, 'expected_original': snippet}


def test_run(repo, args, out):
    if not args:
        return {'status': 'not_configured', 'passed': None, 'failures': None}
    out.mkdir(parents=True, exist_ok=True)
    junit = out / 'pytest.xml'
    try:
        result = command([sys.executable, '-m', 'pytest', *args, f'--junitxml={junit}',
                          f'--basetemp={out.resolve()/"pytest-tmp"}'], repo, 300)
        (out / 'pytest.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        failures = []
        if junit.exists():
            for case in ET.parse(junit).iter('testcase'):
                if case.find('failure') is not None or case.find('error') is not None:
                    failures.append(case.get('classname', '') + '::' + case.get('name', ''))
        cases = list(ET.parse(junit).iter('testcase')) if junit.exists() else []
        count = len(cases)
        errors = sum(case.find('error') is not None for case in cases)
        return {'status': 'passed' if result.returncode == 0 and count else 'failed',
                'returncode': result.returncode, 'tests': count, 'failures': failures,
                'errors': errors, 'infrastructure_error': result.returncode not in (0, 1) or count == 0 or errors > 0}
    except subprocess.TimeoutExpired:
        return {'status': 'timeout', 'passed': False, 'failures': None, 'infrastructure_error': True}


def gates(repo, file_path, original, snippet, patch, condition, pytest_args, baseline_tests, out):
    checks = {}
    if not condition['gates']:
        return True, {'status': 'disabled_by_condition'}
    # Compare the applied change, including preserved decorators, rather than
    # charging a decorator's absence in the model response as deleted code.
    delta = list(difflib.unified_diff(original.decode('utf-8').splitlines(),
                 (repo / file_path).read_text(encoding='utf-8').splitlines(), lineterm=''))
    added = sum(l.startswith('+') and not l.startswith('+++') for l in delta)
    removed = sum(l.startswith('-') and not l.startswith('---') for l in delta)
    size = len([l for l in snippet.splitlines() if l.strip()])
    churn = added + removed
    limit = 5 if size < 15 else min(50, size * 0.5)
    minimal = churn <= limit
    stats = {'lines_added': added, 'lines_removed': removed, 'total_churn': churn,
             'original_length': size, 'limit': limit}
    message = f'{churn} added plus deleted lines; allowed {limit}'
    checks['minimality'] = {'passed': minimal, 'message': message, **stats}
    if not minimal:
        return False, checks
    try:
        compile((repo / file_path).read_text(encoding='utf-8'), file_path, 'exec')
        checks['compile'] = {'passed': True}
    except SyntaxError as exc:
        checks['compile'] = {'passed': False, 'message': str(exc)}
        return False, checks
    # Structured lint errors and an explicit score; no shell output scraping.
    lint_context = lint_options(condition.get('lint_pythonpath'))
    lint = command([sys.executable, '-m', 'pylint', file_path, '--output-format=json2', '--exit-zero', *lint_context], repo, 120)
    try:
        data = json.loads(lint.stdout)
        require_lint_health(data)
        messages = data['messages']
        errors = [m for m in messages if m.get('type') in ('fatal', 'error')]
        target = repo / file_path
        candidate_bytes = target.read_bytes()
        try:
            target.write_bytes(original)
            before_lint = command([sys.executable, '-m', 'pylint', file_path,
                                   '--output-format=json2', '--exit-zero', *lint_context], repo, 120)
            old = json.loads(before_lint.stdout)
            require_lint_health(old)
        finally:
            target.write_bytes(candidate_bytes)
        def identity(m):
            return (m.get('symbol'), m.get('obj'), m.get('message'))
        prior = Counter(identity(m) for m in old['messages'] if m.get('type') in ('fatal', 'error'))
        new_errors = list((Counter(identity(m) for m in errors) - prior).elements())
        checks['pylint'] = {'passed': not new_errors and data['statistics']['score'] >= 2.0,
                            'score': data['statistics']['score'], 'new_errors': new_errors,
                            'preexisting_error_count': sum(prior.values())}
    except (ValueError, KeyError) as exc:
        raise ValidatorInfrastructureError('Validator infrastructure: Pylint unavailable or invalid structured report') from exc
    if not checks['pylint']['passed']:
        return False, checks
    tests = test_run(repo, pytest_args, out)
    checks['pytest'] = tests
    if condition['tests'] == 'block':
        if tests['status'] == 'not_configured' or tests.get('infrastructure_error'):
            return False, checks
        regressions = sorted(set(tests['failures'] or []) - set(baseline_tests['failures'] or []))
        checks['new_test_failures'] = regressions
        if regressions:
            return False, checks
    return True, checks


def repair_one(repo, finding, condition, client, pytest_args, baseline_tests, out, prompt_library=None):
    out.mkdir(parents=True, exist_ok=True)
    file_path = finding['sast']['location']['file_path']
    path = repo / file_path
    before = path.read_bytes()
    snippet, details = current(repo, finding)
    builder = PromptBuilder(condition['guidance'], condition['examples'], condition.get('simple', False), library=prompt_library)
    prompt = builder.build_initial_fix_prompt(finding, {}, snippet, file_path)
    prompt = sanitise(prompt)
    dump(out / 'prompt.json', {'system': SYSTEM_PROMPT, 'user': prompt,
                              'library_version': builder.library_version, 'condition': condition})
    patcher = CodePatcher(repo)
    attempts, previous, feedback = [], '', ''
    accepted = False
    for number in range(1, condition['attempts'] + 1):
        # Every attempt starts from the pre-finding bytes, including after a
        # failed post-application gate. Earlier accepted findings remain intact.
        path.write_bytes(before)
        record = {'attempt': number, 'accepted': False}
        attempts.append(record)
        try:
            user = prompt if number == 1 else builder.build_refinement_prompt(prompt, previous, feedback, finding, number, condition['attempts'])
            started = time.monotonic()
            response = client.chat_completion([{'role': 'user', 'content': user}], system_prompt=SYSTEM_PROMPT)
            record.update(duration_seconds=time.monotonic()-started, response=response, prompt=user)
            dump(out / f'attempt-{number}.json', record)
            patch = patcher.parse_fix_response(response['content'])
            previous = patch['fixed_code']
            applied, message = patcher.apply_fix(file_path, patch, details)
            record['application'] = deepcopy(patcher.last_application)
            if not applied:
                feedback = message
                record['error'] = message
                continue
            ok, validation = gates(repo, file_path, before, snippet, patch, condition, pytest_args, baseline_tests, out / f'tests-{number}')
            record['validation'] = validation
            if not ok:
                feedback = json.dumps(validation, ensure_ascii=False)
                continue
            record['accepted'] = accepted = True
            break
        except Exception as exc:
            record['error'] = feedback = str(exc)
            if isinstance(exc, GenerationLimitError):
                record.update(response=exc.response, duration_seconds=time.monotonic()-started,
                              generation_failure='output_token_limit', prompt=user)
                previous = ''
                feedback = 'The reply exhausted its output limit. Return a shorter complete patch within the same limit.'
            elif isinstance(exc, ModelOutputError):
                record.update(response=exc.response,duration_seconds=time.monotonic()-started,
                              generation_failure='malformed_or_blocked_output',prompt=user)
                previous = ''
                feedback = 'The generation did not contain the required complete patch. Use the specified patch format.'
            # API access failures are not patch-quality measurements. Stop this
            # run rather than converting missing responses to unfixed findings.
            if isinstance(exc, RuntimeError) and (str(exc).startswith('Gemini') or 'API error' in str(exc)):
                record['infrastructure_error'] = True
                break
            if isinstance(exc, ValidatorInfrastructureError):
                record.update(infrastructure_error=True, infrastructure_kind='validator')
                break
        finally:
            if not record['accepted']:
                path.write_bytes(before)
            dump(out / f'attempt-{number}.json', record)
    after = path.read_bytes()
    diff = list(difflib.unified_diff(before.decode('utf-8').splitlines(), after.decode('utf-8').splitlines(), lineterm=''))
    result = {'finding_id': finding['finding_id'], 'accepted': accepted,
              'security_status': 'pending_batch_rescan', 'attempts': attempts,
              'application_counts': dict(patcher.application_counts),
              'lines_added': sum(l.startswith('+') and not l.startswith('+++') for l in diff),
              'lines_removed': sum(l.startswith('-') and not l.startswith('---') for l in diff)}
    (out / 'patch.diff').write_text('\n'.join(diff), encoding='utf-8')
    dump(out / 'result.json', result)
    return result


def finding_counts(repo, sarif):
    return Counter((f['sast']['rule_id'], f['sast']['location']['file_path'],
                    f['sast']['location']['function'] or '<module>') for f in contexts(repo, sarif))


def verify_batch_targets(repo, findings):
    """A missing or uncompilable target cannot count as a security fix."""
    files = {f['sast']['location']['file_path'] for f in findings}
    for file in files:
        path = (repo / file).resolve()
        if not path.is_relative_to(repo.resolve()):
            raise ValueError('Batch target escaped the source tree')
        compile(path.read_bytes(), file, 'exec')


def compare(before, after):
    removed, added = before - after, after - before
    return {'baseline_findings': sum(before.values()), 'remaining_baseline_findings': sum((before & after).values()),
            'resolved_findings': sum(removed.values()), 'new_findings': sum(added.values()),
            'resolution_rate': sum(removed.values()) / sum(before.values()) if before else None,
            'matching': 'multiset of rule, repository-relative file, qualified function; module locations aggregated',
            'resolved_groups': [{'key': list(k), 'count': v} for k, v in removed.items()],
            'new_groups': [{'key': list(k), 'count': v} for k, v in added.items()]}


def behavioral_oracle(source):
    if (source/'vulnerable_app.py').is_file():
        return ROOT/'review/behavioral/test_synthetic.py'
    if (source/'flask_webgoat').is_dir():
        return ROOT/'review/behavioral/test_flask_webgoat.py'
    if (source/'openapi_specs/openapi3.yml').is_file():
        return ROOT/'review/behavioral/test_vampi.py'
    if (source/'pygoat/settings.py').is_file():
        return ROOT/'review/behavioral/test_pygoat.py'
    return None


def run(args):
    config = deepcopy(CONDITIONS[args.condition])
    source = Path(args.repo).resolve()
    verify_input(source,args.sarif,checked)
    # Missing provider configuration must fail before a running artifact exists.
    client = LLMClient(args.provider, args.model, temperature=0.1, max_tokens=args.max_tokens)
    if config['gates']:
        try:
            checked([sys.executable, '-I', '-c', 'import isort; import pylint'], timeout=30)
        except RuntimeError as exc:
            raise ValidatorInfrastructureError('Validator infrastructure: Pylint dependency preflight failed') from exc
    validation_python = getattr(args, 'validation_python', None) or target_python(source)
    validation_environment = describe_environment(validation_python) if validation_python else None
    if validation_environment:
        config['lint_pythonpath'] = validation_environment['site_packages']
    if checked(['git','status','--porcelain','--untracked-files=no'], source):
        raise ValueError('Input source has edits; prepare a pristine pinned clone')
    behavioral_path = behavioral_oracle(source)
    if not args.pytest_args and (source / 'tests').is_dir():
        args.pytest_args = ['tests', '-m', 'not network']
    if not args.pytest_args and behavioral_path:
        args.pytest_args = [str(behavioral_path)]
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    workspace = out / 'source'
    if workspace.exists() and not args.resume:
        raise ValueError('Output already contains a source clone; choose a new run directory')
    library_path = Path(args.guidance_library).resolve() if getattr(args, 'guidance_library', None) else ROOT / 'llm/guidance_library.review-2.json'
    library_bytes = library_path.read_bytes()
    prompt_library = json.loads(library_bytes)
    PromptBuilder(library=prompt_library)  # Validate before writing a running manifest.
    sha = checked(['git', 'rev-parse', 'HEAD'], source)
    if not workspace.exists():
        checked(['git', 'clone', '--local', '--no-hardlinks', source, workspace])
        checked(['git', 'checkout', '--detach', sha], workspace)
    findings = contexts(source, args.sarif, args.zap)
    all_findings = len(findings)
    if args.cross_file_only:
        findings = [f for f in findings if any(file_count(p)>1 for p in taint_paths(f))]
    if args.limit:
        findings = findings[:args.limit]
    raw_contexts = findings
    if args.context_profile == 'compact':
        findings = [compact_context(f) for f in findings]
    # Record full resolved configuration and immutable input identities before calls.
    manifest = {'source_commit': sha, 'source_url': checked(['git', 'remote', 'get-url', 'origin'], source),
                'provider': args.provider, 'model': args.model, 'condition': args.condition,
                'settings': config, 'temperature': 0.1, 'max_tokens': args.max_tokens,
                'thinking_level': 'minimal' if args.model.startswith('gemma-4-') else None,
                'implementation_sha256': implementation_hashes(),
                'validation_environment': validation_environment,
                'lint_environment_sha256': validation_environment['distribution_sha256'] if validation_environment else None,
                'baseline_sarif': str(Path(args.sarif).resolve()), 'sarif_sha256': digest(args.sarif),
                'zap_sha256': digest(args.zap) if args.zap else None,
                'context_profile': args.context_profile, 'cross_file_only': args.cross_file_only,
                'transport_policy':{k:os.getenv(k) for k in ('AVR_INPUT_BUDGET_PER_MINUTE','AVR_REQUEST_BUDGET_PER_MINUTE','AVR_REQUEST_TIMEOUT','AVR_TRANSPORT_RETRIES')},
                'library_sha256': hashlib.sha256(library_bytes).hexdigest(),
                'library_version': prompt_library['version'],
                'minimality_policy': 'applied added+deleted lines <=5 for <15 significant target lines; otherwise <=min(50, 50% of target)',
                'test_policy_sha256': digest(ROOT/'review/test-policy.json'),
                'behavioral_test_sha256': digest(behavioral_path) if behavioral_path else None,
                'python': sys.version, 'pytest_args': args.pytest_args, 'seed': None,
                'repetition': args.repetition, 'eligible_findings': all_findings, 'selected_findings': len(findings),
                'utc': datetime.now(timezone.utc).isoformat(), 'status': 'running',
                'scope': 'new revision; not a reproduction of original paper prompts or models',
                'dast_status': 'not_run', 'sampling': 'cross-file taint pilot' if args.cross_file_only else ('all findings' if not args.limit else 'pilot only; limit applied')}
    prior_results = []
    if args.resume:
        prior = json.loads((out / 'manifest.json').read_text(encoding='utf-8'))
        if prior.get('status') == 'running':
            raise ValueError('The existing run is marked running; do not resume while another process can write to it')
        for key in ('source_commit','provider','model','condition','sarif_sha256','library_sha256',
                    'temperature','max_tokens','thinking_level','selected_findings','pytest_args','zap_sha256',
                    'implementation_sha256','validation_environment','lint_environment_sha256'):
            if prior.get(key) != manifest.get(key):
                raise ValueError(f'Resume configuration changed: {key}')
        if prior.get('context_profile','full') != args.context_profile or prior.get('cross_file_only',False) != args.cross_file_only:
            raise ValueError('Cannot change context or finding selection on resume')
        # Preserve every prior attempt, but retry the interrupted finding from its
        # restored pre-finding state. Successful preceding findings are not replayed.
        prior_results = json.loads((out / 'results.json').read_text(encoding='utf-8'))
        history = prior.get('resume_history', [])
        history.append({'previous_status':prior['status'], 'previous_implementation':prior.get('implementation_sha256'),
                        'utc':manifest['utc'], 'previous_elapsed_seconds':prior.get('elapsed_seconds')})
        manifest['resume_history'] = history
        if prior_results and any(a.get('infrastructure_error') for a in prior_results[-1].get('attempts', [])):
            interrupted = prior_results.pop()
            dump(out / f'interrupted-finding-{len(prior_results)+1:03d}-{len(history)}.json', interrupted)
        manifest['resumed_from_findings'] = len(prior_results)
    dump(out / 'manifest.json', manifest)
    (out / 'prompt-library.json').write_bytes(library_bytes)
    dump(out / 'contexts.json', findings)
    if args.context_profile == 'compact':
        dump(out / 'raw-contexts.json', raw_contexts)
    baseline_path = out / 'baseline-tests.json'
    baseline_tests = json.loads(baseline_path.read_text()) if args.resume and baseline_path.exists() else test_run(workspace, args.pytest_args, out / 'baseline-tests')
    dump(out / 'baseline-tests.json', baseline_tests)
    if behavioral_path:
        dump(out/'baseline-behavioral-tests.json', test_run(workspace, [str(behavioral_path)], out/'baseline-behavioral-tests'))
    results = prior_results
    started = time.monotonic()
    for i, finding in enumerate(findings, 1):
        if i <= len(prior_results):
            continue
        print(f"{args.model} {args.condition}: {i}/{len(findings)} {finding['finding_id']}", flush=True)
        try:
            result = repair_one(workspace, finding, config, client, args.pytest_args, baseline_tests, out / f'finding-{i:03d}', prompt_library=prompt_library)
        except Exception as exc:
            result = {'finding_id': finding['finding_id'], 'accepted': False, 'error': str(exc), 'attempts': []}
        results.append(result)
        dump(out / 'results.json', results)
        if any(a.get('infrastructure_error') for a in result.get('attempts', [])):
            manifest['status'] = ('interrupted_validator_error' if any(
                a.get('infrastructure_kind') == 'validator' for a in result.get('attempts', []))
                else 'interrupted_api_error')
            break
    else:
        manifest['status'] = 'patching_complete'
    manifest['elapsed_seconds'] = time.monotonic()-started
    manifest['accepted_patches'] = sum(r['accepted'] for r in results)
    manifest['processed_findings'] = len(results)
    manifest['post_tests'] = test_run(workspace, args.pytest_args, out / 'post-tests')
    if behavioral_path:
        manifest['behavioral_tests'] = test_run(workspace, [str(behavioral_path)], out/'behavioral-tests')
    if args.rescan and (manifest['status'] == 'patching_complete' or getattr(args, 'checkpoint_rescan', False)):
        try:
            # Batch measurement integrity applies even when C disabled inline
            # compilation: an unextractable source cannot count as fixed.
            verify_batch_targets(workspace, contexts(source, args.sarif))
            post = scan(workspace, out / 'post-sast', args.codeql)
            manifest['sast'] = compare(finding_counts(source, args.sarif), finding_counts(workspace, post))
            manifest['status'] = 'complete' if manifest['status'] == 'patching_complete' else manifest['status']
        except Exception as exc:
            manifest['rescan_error'] = str(exc)
    dump(out / 'manifest.json', manifest)
    policy = json.loads((ROOT/'review/test-policy.json').read_text(encoding='utf-8'))
    export_run(out, policy)
    print(json.dumps({k: manifest[k] for k in ('status','processed_findings','accepted_patches','elapsed_seconds')}, indent=2))
    return manifest


def matrix(args):
    dump(args.out, {'schema': 1, 'conditions': CONDITIONS, 'original_models': ORIGINAL_MODELS,
                   'original_provider': 'openrouter', 'original_model_access': 'not_configured',
                   'available_free_cohort': {'provider': 'gemini', 'models': ['gemma-4-31b-it','gemma-4-26b-a4b-it'],
                                             'pricing_source': 'https://aistudio.google.com/docs/pricing#gemma-4'},
                   'repetitions_planned': 3, 'datasets': ['synthetic-flask','pygoat','vampi'],
                   'plan': [{'dataset': d,'model':m,'condition':c,'repetition':r,'status':'not_run'}
                            for d in ['synthetic-flask','pygoat','vampi'] for m in ORIGINAL_MODELS
                            for c in CONDITIONS for r in range(1,4)]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('scan')
    p.add_argument('--repo', required=True); p.add_argument('--out', required=True); p.add_argument('--codeql')
    p = sub.add_parser('matrix'); p.add_argument('--out', default='review_results/experiment-plan.json')
    p = sub.add_parser('run')
    for name in ('repo','sarif','out','model'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--provider', choices=['gemini','openrouter','ollama','local'], default='gemini')
    p.add_argument('--condition', choices=CONDITIONS, default='A')
    p.add_argument('--zap'); p.add_argument('--limit', type=int)
    p.add_argument('--max-tokens', type=int, default=8192)
    p.add_argument('--repetition', type=int, default=1)
    p.add_argument('--pytest-args', nargs='*', default=[])
    p.add_argument('--rescan', action='store_true'); p.add_argument('--codeql')
    p.add_argument('--resume', action='store_true')
    p.add_argument('--context-profile', choices=('full','compact'), default='full')
    p.add_argument('--cross-file-only', action='store_true')
    p.add_argument('--checkpoint-rescan', action='store_true', help='Also scan an interrupted checkpoint; no overall fix rate is reported')
    p.add_argument('--guidance-library', help='Versioned JSON library; the exact input is saved with its SHA256')
    p.add_argument('--validation-python', help='Owner-provisioned target interpreter for lint imports; defaults to the dedicated PyGoat/VAmPI environment when available')
    args = parser.parse_args()
    if args.action == 'run':
        manifest = run(args)
        if manifest['status'] not in ('complete','patching_complete') or (args.rescan and manifest['status'] != 'complete'):
            raise SystemExit(2)
    elif args.action == 'scan': print(scan(args.repo, args.out, args.codeql))
    else: matrix(args)


if __name__ == '__main__':
    main()
