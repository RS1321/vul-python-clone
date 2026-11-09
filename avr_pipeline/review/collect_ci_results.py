"""Verify and import compact CI evidence; never overwrite a different attempt."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import zipfile
from urllib.parse import urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]


def unpack(archive, metadata, results, protocol):
    raw = archive.read_bytes()
    if metadata.get('digest') != 'sha256:'+hashlib.sha256(raw).hexdigest():
        raise ValueError('GitHub artifact ZIP checksum differs')
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        names = [name for name in outer.namelist() if name.endswith('.tar.xz')]
        if len(names) != 1:
            raise ValueError('Expected exactly one compact evidence archive')
        data = outer.read(names[0])
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as bundle:
        members = bundle.getmembers()
        roots = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or '..' in path.parts or '\\' in member.name
                    or not path.parts or not re.fullmatch(r'[A-Za-z0-9._-]+', path.parts[0])):
                raise ValueError('Unsafe measurement archive member')
            roots.add(path.parts[0])
        if len(roots) != 1 or sum(m.size for m in members) > 128*1024*1024:
            raise ValueError('Unexpected evidence archive scope or size')
        name = roots.pop()
        manifest_member = next((m for m in members if m.name == name+'/manifest.json'), None)
        manifest = json.loads(bundle.extractfile(manifest_member).read()) if manifest_member else None
        if manifest:
            agent = manifest.get('condition') == 'tool_agent'
            implementation_matches = (manifest.get('implementation_sha256',{}).get('review/runner.py') == protocol['primary_implementation_sha256'].get('review/runner.py') if agent else
                                      manifest.get('implementation_sha256') == protocol['primary_implementation_sha256'])
            if not implementation_matches:
                raise ValueError('CI implementation differs from declared protocol')
            fields = ('max_tokens', 'library_sha256', 'test_policy_sha256')+(() if agent else ('context_profile',))
            for field in fields:
                if manifest.get(field) != protocol[field]:
                    raise ValueError('CI configuration differs: '+field)
            if manifest.get('provider') != 'local':
                raise ValueError('This collector accepts local-model CI evidence only')
            target = results/name
            if target.exists():
                identical = all((target/Path(*PurePosixPath(m.name).parts[1:])).is_file() and
                    (target/Path(*PurePosixPath(m.name).parts[1:])).read_bytes() == bundle.extractfile(m).read()
                    for m in members)
                if identical:
                    return {'artifact_id':metadata['id'], 'run':name, 'status':'already_imported'}
                target = results/(name+'-ci-'+str(metadata['id']))
                if target.exists():
                    raise ValueError('A different retry is already stored at its artifact-specific path')
        else:
            target = results/'ci-bootstrap-failures'/str(metadata['id'])/name
        target.mkdir(parents=True, exist_ok=True)
        for member in members:
            destination = target.joinpath(*PurePosixPath(member.name).parts[1:])
            if not destination.resolve().is_relative_to(target.resolve()):
                raise ValueError('Evidence destination escapes run directory')
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = bundle.extractfile(member).read()
            if destination.exists() and destination.read_bytes() != content:
                raise ValueError('Refusing to overwrite different evidence')
            destination.write_bytes(content)
        provenance = {'artifact':metadata, 'zip_sha256':hashlib.sha256(raw).hexdigest(),
                      'imported_utc':datetime.now(timezone.utc).isoformat(), 'source_clone_included':False}
        (target/'github-artifact-provenance.json').write_text(json.dumps(provenance,indent=2))
    return {'artifact_id':metadata['id'], 'run':target.name,
            'status':manifest.get('status') if manifest else 'bootstrap_failed'}


def fetch(row, root):
    url = row['download_url']
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not (parsed.hostname or '').endswith('.oaiusercontent.com'):
        raise ValueError('Expected the connector-provided artifact download host')
    target = root/(str(row['artifact']['id'])+'.zip')
    if target.exists():
        return target
    pending = target.with_suffix('.partial')
    size = 0
    with requests.get(url, stream=True, timeout=(30,120)) as response:
        response.raise_for_status()
        with pending.open('wb') as handle:
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > 2*1024*1024:
                    raise ValueError('Artifact exceeds the declared compact storage budget')
                handle.write(chunk)
    pending.replace(target)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch-stdin', action='store_true')
    args = parser.parse_args()
    if not args.fetch_stdin:
        parser.error('Supply connector download references on stdin')
    rows = json.load(sys.stdin)
    cache = ROOT/'.review-work/downloaded-study-artifacts'
    cache.mkdir(parents=True, exist_ok=True)
    results = ROOT/'review_results'
    protocol = json.loads((ROOT/'review/study-protocol.validated.json').read_text())
    index_path = results/'ci-imports.json'
    imported = json.loads(index_path.read_text()) if index_path.exists() else []
    for row in rows:
        if any(r['artifact_id'] == row['artifact']['id'] for r in imported):
            continue
        try:
            archive = fetch(row, cache)
            record = unpack(archive, row['artifact'], results, protocol)
        except Exception as error:
            # Signed temporary URLs never enter logs or permanent metadata.
            record = {'artifact_id':row['artifact']['id'], 'status':'import_error', 'error_type':type(error).__name__}
            print(json.dumps(record),flush=True)
            continue
        imported.append(record)
        index_path.write_text(json.dumps(imported,indent=2))
        print(json.dumps(record),flush=True)


if __name__ == '__main__':
    main()
