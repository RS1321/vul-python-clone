"""Resolve the benchmark in sibling-workspace and nested repository layouts."""
from pathlib import Path
import os
import shutil
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def tool_path(name):
    """Use explicit installation paths, PATH, or a separately provisioned tool root."""
    if os.getenv('CODEQL_BIN') and name == 'codeql':
        return os.environ['CODEQL_BIN']
    found = shutil.which(name)
    if found:
        return found
    root = Path(os.getenv('AVR_TOOL_ROOT', str(ROOT)))
    suffix = '.exe' if os.name == 'nt' else ''
    return str(root / f'.review-work/codeql-cli/codeql/{name}{suffix}')


def query_pack_root():
    return Path(os.getenv('CODEQL_PACK_ROOT', str(Path(os.getenv('AVR_TOOL_ROOT', str(ROOT))) / '.review-work/packs')))


def verify_input(repo, sarif, read_git, expected_dataset=None):
    """A registered scan must match both its pinned source and its exact bytes."""
    repo, sarif = Path(repo).resolve(), Path(sarif).resolve()
    manifest = sarif.parent/'dataset-manifest.json'
    if not manifest.exists():
        if expected_dataset:
            raise ValueError('Registered dataset manifest is missing; prepare the pinned input first')
        return None  # Ad-hoc runs still record their source/SARIF hashes.
    record = json.loads(manifest.read_text(encoding='utf-8'))
    if expected_dataset and record.get('dataset') != expected_dataset:
        raise ValueError('Dataset identity differs from the selected baseline')
    if hashlib.sha256(sarif.read_bytes()).hexdigest() != record['sarif_sha256']:
        raise ValueError('SARIF hash differs from registered baseline')
    if read_git(['git','rev-parse','HEAD'],repo) != record['source_commit']:
        raise ValueError('Source differs from pinned baseline; run prepare_inputs.py instead of scanning the current application repository')
    if read_git(['git','status','--porcelain','--untracked-files=no'],repo):
        raise ValueError('Pinned input has tracked source edits')
    return record


def synthetic_repo():
    override = os.getenv('AVR_SYNTHETIC_REPO')
    if override:
        return Path(override).resolve()
    if (ROOT / 'benchmarks/synthetic/.git').exists():
        return ROOT / 'benchmarks/synthetic'
    if (ROOT.parent / 'vulnerable_app.py').is_file():
        return ROOT.parent
    return ROOT.parent / 'vul-python-clone'
