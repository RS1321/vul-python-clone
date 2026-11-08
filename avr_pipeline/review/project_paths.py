"""Resolve the benchmark in sibling-workspace and nested repository layouts."""
from pathlib import Path
import os
import shutil

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


def synthetic_repo():
    override = os.getenv('AVR_SYNTHETIC_REPO')
    if override:
        return Path(override).resolve()
    if (ROOT / 'benchmarks/synthetic/.git').exists():
        return ROOT / 'benchmarks/synthetic'
    if (ROOT.parent / 'vulnerable_app.py').is_file():
        return ROOT.parent
    return ROOT.parent / 'vul-python-clone'
