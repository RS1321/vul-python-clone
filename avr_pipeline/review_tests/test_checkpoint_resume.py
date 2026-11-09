from copy import deepcopy
import json
from pathlib import Path

import pytest

from review import runner
from review.continuation_state import (ContinuationIntegrityError, carried_attempts,
                                      verify_generation_reference)
from review.protocol_compatibility import budget_violations
from review.evidence_io import durable_dump

FINDING = {'finding_id':'fixture','sast':{'cwe':'CWE-089','rule_id':'fixture',
    'description':'fixture','location':{'file_path':'app.py','function':'f','start_line':1,'end_line':2}}}
INITIAL = b'def f():\n    return 1\n'


@pytest.fixture(autouse=True)
def recorded_io(monkeypatch):
    monkeypatch.setattr(runner,'dump',durable_dump)


def response(number):
    return {'content':f'SCOPE: function\n```python\ndef f():\n    return {number}\n```',
            'model':'fixture','usage':{'completion_tokens':10}}


class Client:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.messages = []
    def chat_completion(self, messages, system_prompt=None):
        self.messages.append(deepcopy(dict(messages=messages,system=system_prompt)))
        value = next(self.replies)
        if isinstance(value,Exception):
            raise value
        return deepcopy(value)


def first_reply(kind):
    if kind=='limit':
        return runner.GenerationLimitError(dict(content='partial',model='fixture',usage={}))
    if kind=='blocked':
        return runner.ModelOutputError(dict(content='',finish_reason='SAFETY',model='fixture'))
    if kind=='format':
        return dict(content='no patch block',model='fixture')
    return response(2)


def fixture_gates(repo, file_path, *args, **kwargs):
    passed = 'return 4' in (repo/file_path).read_text(encoding='utf-8')
    return passed, {'minimality':{'passed':passed,'message':'fixture rejection' if not passed else 'fixture accepted'}}


def invoke(repo, out, client, condition, prior=None, implementation=runner.repair_one):
    library = json.loads((runner.ROOT/'llm/guidance_library.review-2.json').read_text(encoding='utf-8'))
    kwargs = dict(prompt_library=library)
    if prior is not None:
        kwargs['prior_attempts'] = prior
    return implementation(repo,deepcopy(FINDING),runner.CONDITIONS[condition],client,[],{},out,**kwargs)


@pytest.mark.parametrize('condition',['A','B','no_guidance','no_examples','A_strict'])
@pytest.mark.parametrize('kind',['gated','format','limit','blocked'])
def test_interrupted_replies_preserve_prompts_patch_and_remaining_budget(tmp_path,monkeypatch,condition,kind):
    monkeypatch.setattr(runner,'gates',fixture_gates)
    reference_repo, resumed_repo = tmp_path/'reference',tmp_path/'resumed'
    for repo in (reference_repo,resumed_repo):
        repo.mkdir();(repo/'app.py').write_bytes(INITIAL)
    normal = Client([first_reply(kind),response(3),response(4)])
    expected = invoke(reference_repo,tmp_path/'normal',normal,condition)
    first = Client([first_reply(kind),RuntimeError('Gemini HTTP 500: fixture outage')])
    out = tmp_path/'continued'
    interrupted = invoke(resumed_repo,out,first,condition)
    history = 'interrupted-finding-001-1.json'
    runner.dump(out/history,interrupted)
    prior = carried_attempts(interrupted,history)
    assert len(prior)==1 and (resumed_repo/'app.py').read_bytes()==INITIAL
    verify_generation_reference(out,prior[0])
    second = Client([response(3),response(4)])
    actual = invoke(resumed_repo,out,second,condition,prior)
    assert first.messages[:1]+second.messages==normal.messages
    assert (resumed_repo/'app.py').read_bytes()==(reference_repo/'app.py').read_bytes()
    assert actual['accepted']==expected['accepted'] is True
    assert actual['application_counts']==expected['application_counts']
    assert [a['attempt'] for a in actual['attempts']]==[1,2,3]
    assert len(second.messages)==2
    runner.dump(out/'results.json',[actual]);runner.dump(out/'manifest.json',{'settings':{'attempts':3}})
    assert budget_violations(out)==[]


def test_two_outages_do_not_duplicate_or_hide_generations(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'gates',fixture_gates)
    repo=tmp_path/'repo';repo.mkdir();(repo/'app.py').write_bytes(INITIAL)
    out=tmp_path/'run'
    one=invoke(repo,out,Client([response(2),RuntimeError('Gemini HTTP 500')]),'A')
    h1='interrupted-finding-001-1.json';runner.dump(out/h1,one)
    two=invoke(repo,out,Client([response(3),RuntimeError('Gemini HTTP 500')]),'A',carried_attempts(one,h1))
    h2='interrupted-finding-001-2.json';runner.dump(out/h2,two)
    last=Client([response(4)])
    three=invoke(repo,out,last,'A',carried_attempts(two,h2))
    runner.dump(out/'results.json',[three]);runner.dump(out/'manifest.json',{'settings':{'attempts':3}})
    assert three['accepted'] and len(last.messages)==1 and budget_violations(out)==[]
    forged=deepcopy(three);forged['attempts'][0]['response']['content']='changed'
    runner.dump(out/'results.json',[forged])
    assert budget_violations(out)[0]['reason']=='invalid continued-generation evidence'


def test_changed_source_fails_before_any_new_request(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'gates',fixture_gates)
    repo=tmp_path/'repo';repo.mkdir();(repo/'app.py').write_bytes(INITIAL)
    out=tmp_path/'run'
    interrupted=invoke(repo,out,Client([response(2),RuntimeError('Gemini HTTP 500')]),'A')
    h='interrupted-finding-001-1.json';runner.dump(out/h,interrupted)
    (repo/'app.py').write_text('def f():\n    return 42\n',encoding='utf-8')
    client=Client([])
    with pytest.raises(ContinuationIntegrityError,match='prompts differ'):
        invoke(repo,out,client,'A',carried_attempts(interrupted,h))
    assert not client.messages


def test_remaining_rejections_exhaust_the_original_cap(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'gates',lambda *a,**k:(False,{'minimality':{'passed':False,'message':'fixture rejection'}}))
    repo=tmp_path/'repo';repo.mkdir();(repo/'app.py').write_bytes(INITIAL)
    out=tmp_path/'run'
    first=invoke(repo,out,Client([response(2),RuntimeError('Gemini HTTP 500')]),'A')
    history='interrupted-finding-001-1.json';runner.dump(out/history,first)
    client=Client([response(3),response(4)])
    result=invoke(repo,out,client,'A',carried_attempts(first,history))
    assert not result['accepted'] and len(result['attempts'])==3 and len(client.messages)==2
    assert (repo/'app.py').read_bytes()==INITIAL
