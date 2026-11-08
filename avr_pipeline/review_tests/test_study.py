import json
from pathlib import Path
import pytest
from review.study_statistics import paired, wilson, repeated_cluster_ci, holm
from review.outcomes import make_rows, test_changes as classify_changes
from review.matrix_study import parser, build_plan
from review.agent_baseline import Tools


def test_exact_mcnemar_and_effect_sizes():
    a = {str(i): i < 8 for i in range(10)}
    b = {str(i): i < 2 for i in range(10)}
    result = paired(a, b)
    assert result['a_only'] == 6 and result['b_only'] == 0
    assert result['mcnemar_exact_p'] == pytest.approx(0.03125)
    assert result['risk_difference'] == .6
    assert result['odds_ratio_boundary'] == 'infinite'
    assert paired({'x': None}, {'x': True})['n'] == 0
    assert wilson(0, 0) is None
    assert wilson(5, 10) == pytest.approx([.236593, .763407], abs=1e-6)
    assert holm([.01, .04, None, .03]) == [.03, .06, None, .06]


def test_repeated_intervals_require_three_real_repetitions():
    assert repeated_cluster_ci([.2]) is None
    assert repeated_cluster_ci([.1, .2]) is None
    assert repeated_cluster_ci([.1, .2, .3]) == repeated_cluster_ci([.1, .2, .3])


def test_repeat_tags_and_frozen_equal_budget():
    args = parser().parse_args(['--dataset', 'synthetic', 'vampi', '--model', 'fixture', '--provider', 'local', '--tag', 'r2'])
    plan = build_plan(args)
    assert plan['repetitions'] == [2]
    assert len(plan['cells']) == 14
    assert plan['max_tokens'] == 8192 and plan['library_version'] == 'review-2'
    args.tag = 'study'
    assert len(build_plan(args)['cells']) == 42
    args.provider = 'openrouter'
    with pytest.raises(ValueError, match='free'):
        build_plan(args)


def f(identity):
    return {'finding_id': identity, 'sast': {'rule_id': 'r', 'cwe': 'CWE-1',
            'location': {'file_path': 'app.py', 'function': 'f'}}}


def test_partial_duplicate_identity_and_missing_behavior_stay_unknown():
    m = {'status': 'complete', 'sast': {'resolved_groups': [{'key': ['r', 'app.py', 'f'], 'count': 1}], 'new_findings': 0},
         'post_tests': {'status': 'passed', 'failures': []}}
    rows = make_rows([f('one'), f('two')], [], m, {'status': 'passed', 'failures': []})
    assert all(r['resolved'] is None and r['joint_security'] is None for r in rows)
    rows = make_rows([f('one')], [], m, {'status': 'passed', 'failures': []})
    assert rows[0]['resolved'] is True and rows[0]['joint_security'] is None
    m['behavioral_tests'] = {'status': 'passed', 'tests': 3}
    assert make_rows([f('one')], [], m, {'status': 'passed', 'failures': []})[0]['joint_security'] is True
    m['sast']['new_findings'] = 1
    assert make_rows([f('one')], [], m, {'status': 'passed', 'failures': []})[0]['joint_security'] is False


def test_fixed_test_policy_does_not_discard_unlisted_failures():
    change = classify_changes({'status': 'passed', 'failures': []}, {'status': 'failed', 'failures': ['old', 'new']},
                          {'vulnerable_behavior_tests': {'old': 'Exact reviewed reason'}})
    assert change['regressions'] == 1 and change['old_behavior_failures'] == 1
    assert classify_changes({}, {'status': 'failed', 'failures': None})['regressions'] is None


def test_agent_tools_reject_shell_paths_and_test_rewriting(tmp_path, monkeypatch):
    (tmp_path/'app.py').write_text('value = 1\n')
    (tmp_path/'tests').mkdir()
    (tmp_path/'tests/test_app.py').write_text('assert True\n')
    import review.agent_baseline as module
    monkeypatch.setattr(module, 'checked', lambda *args: 'app.py\ntests/test_app.py\n.env')
    tools = Tools(tmp_path, tmp_path/'out', [])
    with pytest.raises(ValueError):
        tools.invoke('shell', {'command': 'anything'})
    for path in ['../outside.py', '.env', 'tests/test_app.py']:
        with pytest.raises(ValueError):
            tools.invoke('replace_text', {'path': path, 'old': 'assert True', 'new': 'assert False'})
    tools.invoke('replace_text', {'path': 'app.py', 'old': 'value = 1', 'new': 'value = 2'})
    assert (tmp_path/'app.py').read_text() == 'value = 2\n'
    with pytest.raises(ValueError):
        tools.invoke('replace_text', {'path': 'app.py', 'old': 'missing', 'new': 'x'})


def test_native_tool_turn_preserves_provider_signature(monkeypatch):
    import review.tool_client as module
    monkeypatch.setenv('GEMINI_API_KEY', 'fixture-key-never-sent-to-network')
    monkeypatch.setenv('AVR_AGENT_REQUEST_INTERVAL', '0')
    monkeypatch.setattr(module, 'reserve', lambda *args: 0)
    calls = []
    def post(url, **kwargs):
        calls.append(json.loads(json.dumps(kwargs['json'])))
        action = {'tool':'list_files' if len(calls)==1 else 'finish', 'arguments':{}}
        body = {'modelVersion':'fixture', 'candidates':[{'finishReason':'STOP','content':{'role':'model','parts':[
            {'thoughtSignature':'signature-fixture','functionCall':{'name':'repository_action','args':action}}]}}]}
        return type('Response', (), {'status_code':200, 'json':lambda self:body})()
    monkeypatch.setattr(module.requests, 'post', post)
    client = module.ToolClient('gemini', 'fixture', max_tokens=8192)
    messages = [{'role':'user','content':'Inspect the local repository.'}]
    first = client.chat_completion(messages)
    messages += [{'role':'assistant','content':first['content']}, {'role':'user','content':'app.py'}]
    second = client.chat_completion(messages)
    assert json.loads(second['content'])['tool'] == 'finish'
    assert calls[1]['contents'][1]['parts'][0]['thoughtSignature'] == 'signature-fixture'
    assert calls[1]['contents'][2]['parts'][0]['functionResponse']['name'] == 'repository_action'
    assert calls[1]['generationConfig']['maxOutputTokens'] == 8192


def test_analysis_keeps_unfinished_agent_unmeasured(tmp_path):
    from review.analyze_study import analyze
    out = tmp_path/'active-agent'
    out.mkdir()
    (out/'manifest.json').write_text(json.dumps({'status':'running','condition':'tool_agent','model':'fixture'}))
    (out/'contexts.json').write_text(json.dumps([f('one')]))
    result = analyze(tmp_path)
    assert result['full_runs'] == 0
    rows = json.loads((out/'finding-outcomes.json').read_text())
    assert rows[0]['resolved'] is None and rows[0]['attempts'] is None


def test_behavioral_infrastructure_error_never_becomes_security_evidence():
    m = {'status':'complete','sast':{'resolved_groups':[{'key':['r','app.py','f'],'count':1}], 'new_findings':0},
         'post_tests':{'status':'passed','failures':[]},
         'behavioral_tests':{'status':'failed','tests':1,'infrastructure_error':True}}
    row = make_rows([f('one')],[],m,{'status':'passed','failures':[]})[0]
    assert row['resolved'] is True and row['behavioral_assertions_pass'] is None and row['joint_security'] is None


def test_target_probe_is_isolated_from_repository_modules(tmp_path, monkeypatch):
    import sys
    from review.target_environment import describe
    (tmp_path/'json.py').write_text('raise RuntimeError("Repository code must not execute during environment probing")')
    monkeypatch.chdir(tmp_path)
    info = describe(sys.executable)
    assert info['site_packages'] and len(info['distribution_sha256']) == 64


def test_matrix_does_not_reuse_different_implementation(tmp_path):
    from review.matrix_study import execute
    args = parser().parse_args(['--dataset','vampi','--model','fixture','--provider','local','--tag','r2','--results',str(tmp_path)])
    plan = build_plan(args)
    out = tmp_path/plan['cells'][0]['run']
    out.mkdir()
    (out/'manifest.json').write_text(json.dumps({'implementation_sha256':{'old':'hash'},'status':'complete'}))
    with pytest.raises(ValueError,match='Implementation changed'):
        execute(plan['cells'][0],args,plan)


def test_daily_quota_defers_only_affected_model():
    from review.matrix_study import AccessState
    state = AccessState()
    a = {'provider':'gemini','model':'one'}
    b = {'provider':'gemini','model':'two'}
    state.observe(a,['HTTP 429: Generate content requests per day limit exceeded'])
    assert state.reason(a) == 'daily_quota' and state.reason(b) is None
    for i in range(3):
        state.observe(b,['Gemini HTTP 503 unavailable'])
    assert state.reason(b) == 'provider_unavailable'


def test_request_count_budget_works_without_token_budget(tmp_path, monkeypatch):
    import request_budget as budget
    class Clock:
        now = 1000
        def time(self): return self.now
        def monotonic(self): return self.now
        def sleep(self,seconds): self.now += seconds
    clock = Clock()
    monkeypatch.setattr(budget,'time',clock)
    monkeypatch.setenv('AVR_INPUT_BUDGET_PER_MINUTE','0')
    monkeypatch.setenv('AVR_REQUEST_BUDGET_PER_MINUTE','1')
    monkeypatch.setenv('AVR_REQUEST_LEDGER_DIR',str(tmp_path))
    assert budget.reserve('fixture',{}) == 0
    assert budget.reserve('fixture',{}) >= 61


def test_acknowledged_malformed_generation_is_not_an_api_outage(monkeypatch):
    import llm_client as module
    import request_budget
    monkeypatch.setenv('GEMINI_API_KEY','fixture-key-not-networked')
    monkeypatch.setattr(request_budget,'reserve',lambda *args:0)
    body = {'modelVersion':'fixture','candidates':[{'finishReason':'MALFORMED_FUNCTION_CALL','content':{'parts':[]}}]}
    response = type('Response',(),{'status_code':200,'json':lambda self:body})()
    monkeypatch.setattr(module.requests,'post',lambda *args,**kwargs:response)
    client = module.LLMClient('gemini','fixture')
    with pytest.raises(module.ModelOutputError) as error:
        client.chat_completion([{'role':'user','content':'Repair the local fixture.'}])
    assert error.value.response['finish_reason'] == 'MALFORMED_FUNCTION_CALL'


def test_unconfigured_local_model_fails_before_generation():
    from llm_client import LLMClient
    with pytest.raises(ValueError,match='loopback'):
        LLMClient('local','unconfigured-model')


def test_interrupted_runner_has_failure_exit_status(monkeypatch):
    import sys
    import review.runner as module
    monkeypatch.setattr(sys,'argv',['runner','run','--repo','unused','--sarif','unused','--out','unused','--model','fixture','--rescan'])
    monkeypatch.setattr(module,'run',lambda args:{'status':'interrupted_api_error'})
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2


@pytest.mark.parametrize('tamper', ['source','sarif'])
def test_registered_input_rejects_wrong_source_or_scan(tmp_path,tamper):
    import hashlib
    from review.project_paths import verify_input
    sarif = tmp_path/'scan.sarif'
    sarif.write_text('{}')
    record = {'dataset':'fixture','source_commit':'pinned','sarif_sha256':hashlib.sha256(sarif.read_bytes()).hexdigest()}
    (tmp_path/'dataset-manifest.json').write_text(json.dumps(record))
    if tamper == 'sarif':
        sarif.write_text('{"changed":true}')
    def git_read(args,cwd):
        return 'different' if tamper == 'source' and 'rev-parse' in args else 'pinned' if 'rev-parse' in args else ''
    with pytest.raises(ValueError,match='Source differs|SARIF hash differs'):
        verify_input(tmp_path,sarif,git_read,'fixture')
