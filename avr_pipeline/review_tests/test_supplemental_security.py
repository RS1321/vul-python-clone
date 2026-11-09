import pytest
from review.supplemental_security import changes,counts,suites,measure


def test_unmeasured_supplemental_oracles_are_not_zero_failures():
    assert counts(None) is None
    assert changes(None,[dict(name='one',passed=True,category='security')]) is None
    rows=[dict(name='one',passed=True,category='security'),dict(name='two',passed=False,category='functionality')]
    assert counts(rows)['security']==dict(passed=1,total=1)
    assert counts(rows)['functionality']==dict(passed=0,total=1)


def test_supplemental_changes_pair_exact_assertions_without_imputing_missing_checks():
    row=lambda name,passed:dict(name=name,passed=passed,category='security')
    result=changes([row('fixed',False),row('broken',True),row('missing',True)],
                   [row('fixed',True),row('broken',False),row('new',True)])
    assert result==dict(matched_assertions=2,newly_passing=1,newly_failing=1,added_assertions=1,missing_assertions=1)
    with pytest.raises(ValueError,match='duplicate'):
        changes([row('same',True),row('same',False)],[row('same',True)])


def test_supplemental_lessons_use_django_separately_and_include_targeted_suites(tmp_path):
    for lesson in ['sensitive_data_exposure','xss_lab']:
        (tmp_path/'dockerized_labs'/lesson).mkdir(parents=True)
    result={s[0]:s for s in suites('pygoat',tmp_path)}
    assert result['sensitive_data_exposure'][1]=='pygoat'
    assert result['xss_lab'][1]=='vampi'
    assert 'targeted-xss_lab' in result and 'django-host' in result
    assert result['targeted-xss_lab'][3]==['--kind','xss_lab']


def test_timed_out_oracle_keeps_its_partial_log_and_does_not_report_passing_checks(tmp_path,monkeypatch):
    import subprocess
    import review.supplemental_security as module
    def timeout(*args,**kwargs):
        raise subprocess.TimeoutExpired(args[0],240,output=b'partial output',stderr=b'partial error')
    monkeypatch.setattr(module.subprocess,'run',timeout)
    out=tmp_path/'execution'
    row=measure(tmp_path,out,('suite','vampi','review/lesson_security.py',[],'checks.json'),{'vampi':'unused'},{'fixed':'input'})
    assert row['execution_status']=='timeout' and row['checks'] is None
    assert (out/'runner.log').read_text()=='partial outputpartial error'
    assert measure(tmp_path,out,('suite','vampi','review/lesson_security.py',[],'checks.json'),{'vampi':'unused'},{'fixed':'input'})==row


def test_derived_changes_do_not_mix_security_repairs_and_functional_regressions(tmp_path):
    import json
    from review.supplemental_analysis import enrich
    before=[dict(name='security',category='security',passed=False),dict(name='normal use',category='functionality',passed=True)]
    after=[dict(name='security',category='security',passed=True),dict(name='normal use',category='functionality',passed=False)]
    for folder,checks in [('baseline/pygoat/suite',before),('models/pygoat-m1/suite',after)]:
        directory=tmp_path/folder;directory.mkdir(parents=True)
        (directory/'execution.json').write_text(json.dumps(dict(configuration=dict(suite='suite',script_sha256='fixed'),checks=checks)))
    path=tmp_path/'summary.json'
    raw=dict(source_verification=[dict(model='fixture',dataset='pygoat',case_id='pygoat-m1')],results=[dict(model='fixture',dataset='pygoat',suite='suite')])
    path.write_text(json.dumps(raw))
    row=enrich(path)['results'][0]['matched_changes_by_category']
    assert row['security']['newly_passing']==1 and row['security']['newly_failing']==0
    assert row['functionality']['newly_failing']==1
    assert json.loads(path.read_text())==raw
