import json
from pathlib import Path
import tarfile

import pytest

from review.ci_local_study import package_evidence


def test_archived_measurements_exclude_runtime_clones_and_databases(tmp_path):
    out = tmp_path/'run'
    out.mkdir()
    (out/'manifest.json').write_text('{"status":"complete"}')
    (out/'source').mkdir()
    (out/'source/private.txt').write_text('not evidence')
    (out/'post-sast/codeql-db').mkdir(parents=True)
    (out/'post-sast/codeql-db/huge.bin').write_bytes(b'not evidence')
    (out/'post-sast/scan.sarif').write_text('{}')
    archive = package_evidence(out, tmp_path/'archives')
    with tarfile.open(archive) as bundle:
        assert bundle.getnames() == ['run/manifest.json', 'run/post-sast/scan.sarif']


def test_evidence_is_not_silently_truncated_to_fit_storage_budget(tmp_path):
    out = tmp_path/'run'
    out.mkdir()
    (out/'manifest.json').write_text('{"status":"complete"}')
    with pytest.raises(RuntimeError, match='storage cap'):
        package_evidence(out, tmp_path/'archives', maximum_bytes=1)
    assert not list((tmp_path/'archives').glob('*.tar.xz'))


def test_all_free_local_assets_have_fixed_revisions_and_digests():
    root = Path(__file__).resolve().parents[1]
    assets = json.loads((root/'review/local-study-assets.json').read_text())
    for model in assets['models'].values():
        assert len(model['revision']) == 40 and len(model['sha256']) == 64
        assert model['repo'].startswith('Qwen/')
    assert len(assets['models']) == 4
