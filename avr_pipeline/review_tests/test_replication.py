import ast
from copy import deepcopy
import json
from pathlib import Path
import pytest

from codePatcherAST import CodePatcher
from getFindingContext import get_finding_details
from factorial_prompts import PromptBuilder, ENTRIES
from minimality_validator import validate_fix_minimality
from review import runner


def make(tmp_path, source, name='app.py'):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding='utf-8')
    return path, CodePatcher(tmp_path)


def patch(patcher, code, name='f', file='app.py', **details):
    return patcher.apply_fix(file, {'scope':'function','fixed_code':code},
                             {'function_name':name, **details})


def test_multiline_decorators_and_sequential_drift(tmp_path):
    source = '@route(\n    "/f"\n)\ndef f():\n    return 1\n\ndef g():\n    return 2\n'
    path, p = make(tmp_path, source)
    assert patch(p, 'def f():\n    value = 1\n    return value')[0]
    assert patch(p, 'def g():\n    return 3', name='g')[0]
    assert path.read_text().startswith('@route(\n    "/f"\n)\ndef f():')
    assert len(ast.parse(path.read_text()).body) == 2
    assert p.application_counts['ast_name'] == 2


def test_duplicate_method_names_require_qualification(tmp_path):
    source = 'class A:\n    def f(self):\n        return 1\nclass B:\n    def f(self):\n        return 2\n'
    path, p = make(tmp_path, source)
    assert not patch(p, 'def f(self):\n    return 9')[0]
    assert path.read_text() == source
    assert patch(p, 'def f(self):\n    return 9', name='B.f')[0]
    assert 'return 1' in path.read_text()
    assert p.application_counts['failures'] == 1


def test_async_and_cross_file_targets(tmp_path):
    path, p = make(tmp_path, 'async def f():\n    return 1\n', 'one/api.py')
    other, _ = make(tmp_path, 'async def f():\n    return 2\n', 'two/api.py')
    assert patch(p, 'async def f():\n    return 3', file='one/api.py')[0]
    assert 'return 2' in other.read_text()
    assert not patch(p, 'def f():\n    return 9', file='one/api.py')[0]


@pytest.mark.parametrize('replacement', ['def other():\n    return 2',
    'def f():\n    return 2\ndef added():\n    pass',
    '@new_decorator\ndef f():\n    return 2', 'def f(: pass'])
def test_invalid_application_never_writes(tmp_path, replacement):
    path, p = make(tmp_path, 'def f():\n    return 1\n')
    before = path.read_bytes()
    assert not patch(p, replacement)[0]
    assert path.read_bytes() == before


def test_line_requires_current_snapshot(tmp_path):
    path, p = make(tmp_path, 'debug = True\nvalue = 1\n')
    data = {'scope':'line','fixed_code':'debug = False'}
    assert not p.apply_fix('app.py', data, {'start_line':2, 'expected_original':'debug = True'})[0]
    assert p.apply_fix('app.py', data, {'start_line':1, 'expected_original':'debug = True'})[0]
    assert p.application_counts['verified_line'] == 1


def test_line_scope_cannot_erase_bound_function(tmp_path):
    source='def f():\n    return 1\n'
    path,p=make(tmp_path,source)
    ok,_=p.apply_fix('app.py',{'scope':'line','fixed_code':'value = 2'},
                     {'function_name':'f','start_line':1,'end_line':2,'expected_original':source})
    assert not ok and path.read_text()==source


def test_no_path_escape(tmp_path):
    path, p = make(tmp_path, 'def f():\n    return 1\n')
    assert not patch(p, 'def f():\n    return 2', file='../outside.py')[0]
    assert p.application_counts['failures'] == 1


def test_jit_name_survives_stale_scan_line(tmp_path):
    make(tmp_path, 'def earlier():\n    return 1\n\n\n\n\ndef target():\n    return 2\n')
    finding = {'sast': {'location': {'file_path':'app.py','function':'target','start_line':2,'end_line':2}}}
    details = get_finding_details(finding, str(tmp_path))
    assert 'def target' in details['vulnerable_function_code']
    assert 'def earlier' not in details['vulnerable_function_code']
    finding['sast']['location']['function'] = 'missing'
    assert get_finding_details(finding, str(tmp_path)) is None


def test_factorial_no_guidance_or_example_leakage():
    finding = {'sast': {'cwe':'CWE-89','rule_id':'sql','description':'scanner text'}}
    entry = ENTRIES[89]
    for guidance, examples in [(False,False),(True,False),(False,True),(True,True)]:
        b = PromptBuilder(guidance, examples)
        initial = b.build_initial_fix_prompt(finding, {}, 'def f(): pass', 'app.py')
        retry = b.build_refinement_prompt(initial, 'def f(): pass', 'Compilation failed', finding)
        for text in (initial, retry):
            assert (entry['guidance'] in text) is guidance
            assert (entry['before'] in text) is examples
            assert (entry['after'] in text) is examples
    assert len(ENTRIES) == 18


def test_cwe_normalization():
    assert PromptBuilder().blocks('CWE-089') == PromptBuilder().blocks('CWE-89')


class FakeClient:
    def chat_completion(self, *args, **kwargs):
        return {'content':'SCOPE: function\n```python\ndef f():\n    return 2\n```', 'model':'fixture','usage':{}}


def finding():
    return {'finding_id':'test','sast':{'cwe':'CWE-089','location':{
        'file_path':'app.py','function':'f','start_line':1,'end_line':2}}}


def test_rejected_final_attempt_is_rolled_back(tmp_path, monkeypatch):
    path, _ = make(tmp_path, 'def f():\n    return 1\n')
    before = path.read_bytes()
    monkeypatch.setattr(runner, 'gates', lambda *a: (False, {'pylint':{'passed':False}}))
    result = runner.repair_one(tmp_path, finding(), runner.CONDITIONS['A'], FakeClient(), [], {}, tmp_path/'records')
    assert not result['accepted'] and len(result['attempts']) == 3
    assert path.read_bytes() == before
    assert result['lines_added'] == result['lines_removed'] == 0


def test_disabled_gates_are_explicit_and_patch_is_retained(tmp_path):
    path, _ = make(tmp_path, 'def f():\n    return 1\n')
    result = runner.repair_one(tmp_path, finding(), runner.CONDITIONS['C'], FakeClient(), [], {}, tmp_path/'records')
    assert result['accepted']
    assert 'return 2' in path.read_text()
    assert result['security_status'] == 'pending_batch_rescan'
    assert result['attempts'][0]['validation']['status'] == 'disabled_by_condition'


def test_api_failure_is_infrastructure_failure(tmp_path):
    class Unavailable:
        def chat_completion(self, *args, **kwargs):
            raise RuntimeError('Gemini HTTP 429: quota unavailable')
    path, _ = make(tmp_path, 'def f():\n    return 1\n')
    before = path.read_bytes()
    result = runner.repair_one(tmp_path, finding(), runner.CONDITIONS['A'], Unavailable(), [], {}, tmp_path/'records')
    assert len(result['attempts']) == 1
    assert result['attempts'][0]['infrastructure_error']
    assert path.read_bytes() == before


def test_minimality_rejects_more_than_five_changed_lines():
    ok, _, _ = validate_fix_minimality('def f():\n    return 1',
        'def f():\n    a=1\n    b=2\n    c=3\n    d=4\n    e=5\n    return a+b+c+d+e')
    assert not ok


def test_multiset_comparison_reports_new_findings():
    before = runner.Counter({('sql','a.py','f'):2, ('sql','b.py','f'):1})
    after = runner.Counter({('sql','a.py','f'):1, ('xss','b.py','g'):1})
    result = runner.compare(before, after)
    assert result['resolved_findings'] == 2
    assert result['new_findings'] == 1
    assert result['remaining_baseline_findings'] == 1


@pytest.mark.parametrize('uri', ['../outside.py','https://example.com/a.py','file:///a.py'])
def test_sarif_path_validation(uri):
    with pytest.raises(ValueError): runner.source_path(uri)


def test_gemini_key_is_sent_only_to_google(monkeypatch):
    from llm_client import LLMClient
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    monkeypatch.setenv('OPENAI_API_KEY','fake-gemini-secret')
    calls = []
    class Response:
        status_code = 200
        def json(self):
            return {'modelVersion':'gemma-4-31b-it', 'candidates':[{'finishReason':'STOP','content':{'parts':[{'text':'OK'}]}}],
                    'usageMetadata':{'promptTokenCount':2,'candidatesTokenCount':1,'totalTokenCount':3}}
    def post(url, **kwargs):
        calls.append((url,kwargs)); return Response()
    monkeypatch.setattr('llm_client.requests.post', post)
    result = LLMClient('gemini','gemma-4-31b-it').chat_completion([{'role':'user','content':'OK'}])
    assert result['content'] == 'OK'
    assert calls[0][0].startswith('https://generativelanguage.googleapis.com/')
    assert 'fake-gemini-secret' not in calls[0][0]
    assert calls[0][1]['headers']['x-goog-api-key'] == 'fake-gemini-secret'


def test_silent_model_substitution_is_rejected(monkeypatch):
    from llm_client import LLMClient
    monkeypatch.setenv('GEMINI_API_KEY','fake-key')
    class Response:
        status_code = 200
        def json(self):
            return {'modelVersion':'gemma-4-26b-a4b-it', 'candidates':[{'finishReason':'STOP','content':{'parts':[{'text':'OK'}]}}]}
    monkeypatch.setattr('llm_client.requests.post', lambda *a, **k: Response())
    with pytest.raises(RuntimeError, match='model mismatch'):
        LLMClient('gemini','gemma-4-31b-it').chat_completion([{'role':'user','content':'OK'}])


@pytest.mark.parametrize('status,failures,infra,expected',[
    ('failed',['old'],False,True),
    ('failed',['old','new'],False,False),
    ('failed',[],True,False),
    ('not_configured',None,False,False)])
def test_strict_policy_uses_regressions_and_requires_executed_tests(tmp_path, monkeypatch, status, failures, infra, expected):
    path,_=make(tmp_path,'def f():\n    return 2\n')
    class Lint:
        stdout=json.dumps({'messages':[],'statistics':{'score':9.0}})
    monkeypatch.setattr(runner,'command',lambda *a,**k:Lint())
    monkeypatch.setattr(runner,'test_run',lambda *a,**k:{'status':status,'failures':failures,'infrastructure_error':infra})
    ok,checks=runner.gates(tmp_path,'app.py',b'def f():\n    return 1\n','def f():\n    return 1',
                           {'fixed_code':'def f():\n    return 2'},runner.CONDITIONS['A_strict'],
                           ['tests'],{'failures':['old']},tmp_path/'logs')
    assert ok is expected
    assert path.read_text()=='def f():\n    return 2\n'


def test_batch_oracle_refuses_uncompilable_source_even_if_ast_parses(tmp_path):
    source='return 1\n'
    ast.parse(source)
    make(tmp_path,source)
    with pytest.raises(SyntaxError):
        runner.verify_batch_targets(tmp_path,[finding()])


def test_compact_context_prioritises_cross_file_trace():
    item=finding();item['dast']={}
    def step(file,line):
        return {'location':{'physicalLocation':{'artifactLocation':{'uri':file},'region':{'startLine':line}}}}
    item['sast']['data_flow']=[{'threadFlows':[{'locations':[step('a.py',1),step('a.py',2)]},
                                               {'locations':[step('a.py',1),step('b.py',2)]},
                                               {'locations':[step('a.py',1),step('a.py',3)]}]}]
    compact=runner.compact_context(item)['sast']['data_flow']
    assert compact['omitted_paths']==1
    assert [s['file'] for s in compact['paths'][0]['steps']]==['a.py','b.py']
    assert len(item['sast']['data_flow'][0]['threadFlows'])==3
