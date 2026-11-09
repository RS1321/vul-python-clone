import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from review.collect_ci_results import unpack
from review.collect_github_study import delete_transferred_artifact


class DeleteSession:
    def __init__(self,status=204):
        self.calls=[]
        self.status=status
    def delete(self,url,timeout):
        self.calls.append(url)
        return self
    @property
    def status_code(self):
        return self.status
    def raise_for_status(self):
        raise RuntimeError('remote deletion denied')


@pytest.mark.parametrize('damage',['changed','missing','unimported'])
def test_remote_evidence_survives_an_unverified_local_transfer(tmp_path,damage):
    archive=tmp_path/'123.zip';archive.write_bytes(b'original lossless archive')
    metadata=dict(id=123,digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
    imported=dict(artifact_id=123,run='measured',status='complete')
    if damage=='changed':archive.write_bytes(b'damaged')
    elif damage=='missing':archive.unlink()
    else:imported['artifact_id']=999
    http=DeleteSession()
    with pytest.raises((ValueError,FileNotFoundError)):
        delete_transferred_artifact(http,metadata,archive,imported)
    assert http.calls==[]


@pytest.mark.parametrize('status',[204,404])
def test_remote_deletion_preserves_the_verified_local_archive(tmp_path,status):
    archive=tmp_path/'123.zip';archive.write_bytes(b'original lossless archive')
    metadata=dict(id=123,digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
    http=DeleteSession(status)
    record=delete_transferred_artifact(http,metadata,archive,dict(artifact_id=123,run='measured',status='complete'))
    assert archive.read_bytes()==b'original lossless archive'
    assert record['zip_sha256']==metadata['digest'][7:]
    assert record['remote_status']==('deleted' if status==204 else 'already_absent')
    assert http.calls==['https://api.github.com/repos/RS1321/vul-python-clone/actions/artifacts/123']


def test_remote_deletion_failure_is_not_recorded_as_success(tmp_path):
    archive=tmp_path/'123.zip';archive.write_bytes(b'evidence')
    metadata=dict(id=123,digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(RuntimeError,match='denied'):
        delete_transferred_artifact(DeleteSession(403),metadata,archive,
                                   dict(artifact_id=123,run='measured',status='complete'))
    assert archive.exists()


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


def test_healthy_pre_continuation_results_remain_primary(tmp_path):
    protocol=dict(primary_implementation_sha256={'runner':'new'}, max_tokens=8192,
                  library_sha256='lib', test_policy_sha256='policy', context_profile='compact',
                  continuation_only_compatible_implementations=[dict(implementation_sha256={'runner':'old'},providers=['local'])])
    manifest=dict(implementation_sha256={'runner':'old'},provider='local',status='complete',
                  max_tokens=8192,library_sha256='lib',test_policy_sha256='policy',context_profile='compact')
    archive,metadata=artifact(tmp_path,'healthy',{'healthy/manifest.json':json.dumps(manifest)})
    root=tmp_path/'results'
    assert unpack(archive,metadata,root,protocol)['status']=='complete'
    assert (root/'healthy/manifest.json').exists()
    assert not (root/'local-timeout180-pilots/healthy').exists()
