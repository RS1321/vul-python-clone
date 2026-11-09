import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from review.collect_ci_results import unpack


def artifact(tmp_path, name, files):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:xz') as bundle:
        for path, value in files.items():
            value = value.encode()
            member = tarfile.TarInfo(path)
            member.size = len(value)
            bundle.addfile(member, io.BytesIO(value))
    zip_path = tmp_path/'artifact.zip'
    with zipfile.ZipFile(zip_path, 'w') as outer:
        outer.writestr(name+'.tar.xz', data.getvalue())
    metadata = dict(id=123, digest='sha256:'+hashlib.sha256(zip_path.read_bytes()).hexdigest())
    return zip_path, metadata


def test_collector_rejects_path_escape_before_extraction(tmp_path):
    zip_path, metadata = artifact(tmp_path, 'run', {'run/../../escape.txt':'bad'})
    with pytest.raises(ValueError, match='Unsafe'):
        unpack(zip_path, metadata, tmp_path/'results', {})
    assert not (tmp_path/'escape.txt').exists()


def test_collector_verifies_protocol_and_preserves_different_attempts(tmp_path):
    protocol = dict(primary_implementation_sha256={'runner':'hash'}, max_tokens=8192,
                    library_sha256='lib', test_policy_sha256='policy', context_profile='compact')
    manifest = dict(implementation_sha256={'runner':'hash'}, provider='local', status='complete',
                    max_tokens=8192, library_sha256='lib', test_policy_sha256='policy', context_profile='compact')
    zip_path, metadata = artifact(tmp_path, 'run', {'run/manifest.json':json.dumps(manifest)})
    target = tmp_path/'results'
    assert unpack(zip_path, metadata, target, protocol)['status'] == 'complete'
    assert unpack(zip_path, metadata, target, protocol)['status'] == 'already_imported'
    assert json.loads((target/'run/manifest.json').read_text()) == manifest
    manifest['status'] = 'interrupted_api_error'
    zip_path, metadata = artifact(tmp_path, 'run', {'run/manifest.json':json.dumps(manifest)})
    metadata['id'] = 124
    assert unpack(zip_path, metadata, target, protocol)['run'] == 'run-ci-124'
    assert json.loads((target/'run/manifest.json').read_text())['status'] == 'complete'


def test_collector_rejects_unexpected_reply_budget(tmp_path):
    protocol = dict(primary_implementation_sha256={'runner':'hash'}, max_tokens=8192)
    manifest = dict(implementation_sha256={'runner':'hash'}, max_tokens=1024)
    zip_path, metadata = artifact(tmp_path, 'run', {'run/manifest.json':json.dumps(manifest)})
    with pytest.raises(ValueError, match='max_tokens'):
        unpack(zip_path, metadata, tmp_path/'results', protocol)
