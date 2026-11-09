import pytest

from review.export_public_summary import assert_safe, portable, public_config


def test_as_run_export_omits_raw_messages_and_machine_metadata():
    result=public_config(dict(model='fixture',max_tokens=8192,prompt='private message',
        validation_environment={'site_packages':['C:\\Users\\fixture\\packages']},
        settings=dict(gates=True,attempts=3,lint_pythonpath=['C:\\Users\\fixture\\packages'])))
    assert result['max_tokens']==8192 and result['settings']['gates'] is True
    assert 'prompt' not in result and 'validation_environment' not in result
    assert 'lint_pythonpath' not in result['settings']
    assert_safe(result)


def test_local_paths_are_removed_without_treating_urls_as_drives():
    assert portable('C:\\Users\\fixture\\source.py').startswith('[local path')
    assert portable('/home/runner/work/source.py').startswith('[local path')
    url='https://github.com/RS1321/vul-python-clone'
    assert portable(url)==url
    assert_safe(url)


def test_secret_and_raw_message_fields_fail_closed():
    with pytest.raises(ValueError):assert_safe({'response':'private'})
    with pytest.raises(ValueError):assert_safe('AIza'+'a'*35)
    assert_safe('gemma-A-flask-webgoat-review2-validated-r1')
