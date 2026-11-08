"""Resolve lint imports against the same dedicated environment used for execution.

Only an owner-provisioned interpreter is probed. Repository files cannot nominate
an interpreter or supply executable hooks. Secrets are stripped from the probe.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def target_python(source):
    source = Path(source)
    kind = 'vampi' if (source/'openapi_specs/openapi3.yml').exists() else 'pygoat' if (source/'pygoat/settings.py').exists() else None
    if not kind:
        return None
    root = Path(os.getenv('AVR_TOOL_ROOT', str(ROOT)))
    relative = f'.review-work/{kind}-env/' + ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    path = Path(os.getenv(f'AVR_{kind.upper()}_PYTHON', str(root/relative)))
    return path.resolve() if path.is_file() else None


def describe(executable):
    program = ('import json,site,sys; from importlib.metadata import distributions; '
               'print(json.dumps({"python":sys.version,"site_packages":site.getsitepackages(),'
               '"packages":sorted({d.metadata["Name"]+"=="+d.version for d in distributions() if d.metadata.get("Name")})}))')
    env = {k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential',k,re.I)}
    result = subprocess.run([str(Path(executable).resolve()), '-I', '-c', program], env=env,
                            capture_output=True, text=True, encoding='utf-8', timeout=30, check=True)
    record = json.loads(result.stdout)
    record['site_packages'] = [str(Path(p).resolve()) for p in record['site_packages'] if Path(p).is_dir()]
    record['distribution_sha256'] = hashlib.sha256(json.dumps(record['packages'],sort_keys=True).encode()).hexdigest()
    record['executable'] = str(Path(executable).resolve())
    return record


def lint_options(paths):
    if not paths:
        return []
    resolved = [str(Path(p).resolve()) for p in paths]
    if any(not Path(p).is_dir() for p in resolved):
        raise ValueError('Validation environment path is missing')
    # A fixed expression with quoted string literals; never passed through a shell.
    return ['--init-hook', 'import sys; sys.path[:0] = '+repr(resolved)]
