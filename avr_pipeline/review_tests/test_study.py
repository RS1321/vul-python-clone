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
