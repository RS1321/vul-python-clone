import json
import shutil
import subprocess
import sys

import pytest

from llm.patchset import apply_patchset, sha256


def edit(path, before, after):
    return {'path': path.name, 'sha256': sha256(path.read_bytes()), 'before': before, 'after': after}


def test_two_module_contract_requires_both_edits_and_rolls_back(tmp_path):
    encoder = tmp_path / 'encoder.py'
    decoder = tmp_path / 'decoder.py'
    encoder.write_text('def encode(value):\n    return {"old": value}\n')
    decoder.write_text('def decode(value):\n    return value["old"]\n')
    changes = [edit(encoder, '"old"', '"current"'), edit(decoder, '"old"', '"current"')]
    def check(root):
        proc = subprocess.run([sys.executable, '-B', '-c',
            'from encoder import encode; from decoder import decode; assert decode(encode([1, 2])) == [1, 2]'],
            cwd=root, capture_output=True, text=True)
        return {'passed': proc.returncode == 0}
    before = encoder.read_bytes()
    rejected = apply_patchset(tmp_path, changes[:1], check)
    assert not rejected['accepted'] and rejected['rolled_back']
    assert encoder.read_bytes() == before
    accepted = apply_patchset(tmp_path, changes, check)
    assert accepted['accepted'] and len(accepted['files']) == 2


def test_stale_later_file_prevents_every_write(tmp_path):
    one, two = tmp_path / 'one.py', tmp_path / 'two.py'
    for p in (one, two):
        p.write_text('value = 1\n')
    changes = [edit(p, '1', '2') for p in (one, two)]
    changes[1]['sha256'] = 'stale'
    result = apply_patchset(tmp_path, changes, lambda _: {'passed': True})
    assert not result['accepted'] and not result['rolled_back']
    assert one.read_text() == two.read_text() == 'value = 1\n'


def test_javascript_syntax_and_runtime_contract(tmp_path):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the JavaScript runtime check')
    source = tmp_path / 'format.js'
    source.write_text('module.exports = value => ({label: value});\n')
    invalid = edit(source, '({label: value})', '({label: value)')
    assert not apply_patchset(tmp_path, [invalid], lambda _: {'passed': True})['accepted']
    valid = edit(source, 'label:', 'name:')
    def check(root):
        proc = subprocess.run([node, '-e',
            "const f=require('./format'); if(f('hello').name !== 'hello') process.exit(1)"], cwd=root)
        return {'passed': proc.returncode == 0}
    assert apply_patchset(tmp_path, [valid], check)['accepted']


def test_validation_exception_restores_all_bytes(tmp_path):
    path = tmp_path / 'app.py'
    path.write_bytes(b'value = 1\r\n')
    before = path.read_bytes()
    def check(_):
        raise RuntimeError('project check crashed')
    with pytest.raises(RuntimeError):
        apply_patchset(tmp_path, [edit(path, '1', '2')], check)
    assert path.read_bytes() == before


def test_python_context_error_rejected_before_writing(tmp_path):
    path = tmp_path / 'app.py'
    path.write_text('value = 1\n')
    result = apply_patchset(tmp_path, [edit(path, 'value = 1', 'return 1')], lambda _: {'passed': True})
    assert not result['accepted'] and path.read_text() == 'value = 1\n'


def test_validation_cannot_silently_change_accepted_source(tmp_path):
    path = tmp_path / 'app.py'
    path.write_text('value = 1\n')
    def check(_):
        path.write_text('value = 999\n')
        return {'passed': True}
    result = apply_patchset(tmp_path, [edit(path, '1', '2')], check)
    assert not result['accepted'] and result['rolled_back']
    assert path.read_text() == 'value = 1\n'


def test_transient_file_lock_during_rollback_restores_both_files(tmp_path, monkeypatch):
    import llm.patchset as patchset
    one, two = tmp_path / 'one.py', tmp_path / 'two.py'
    for path in (one, two):
        path.write_bytes(b'value = 1\r\n')
    edits = [edit(path, '1', '2') for path in (one, two)]
    replace = patchset.os.replace
    locked = []
    def temporarily_locked(source, destination):
        if str(destination) == str(one) and b'value = 1' in __import__('pathlib').Path(source).read_bytes() and len(locked) < 2:
            locked.append(True)
            raise PermissionError('Temporary sharing violation during rollback')
        return replace(source, destination)
    monkeypatch.setattr(patchset.os, 'replace', temporarily_locked)
    monkeypatch.setattr(patchset.time, 'sleep', lambda _: None)
    result = apply_patchset(tmp_path, edits, lambda _: {'passed': False})
    assert not result['accepted'] and result['rolled_back'] and len(locked) == 2
    assert one.read_bytes() == two.read_bytes() == b'value = 1\r\n'
