"""Expose each existing external behavioral assertion as an individual pytest case."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def collect(kind):
    root = Path(os.getenv('AVR_TOOL_ROOT', str(ROOT)))
    relative = f'.review-work/{kind}-env/' + ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    executable = os.getenv(f'AVR_{kind.upper()}_PYTHON', str(root/relative))
    if not Path(executable).exists():
        executable = sys.executable
    env = {k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    with tempfile.TemporaryDirectory(prefix='avr-oracle-') as temp:
        out = Path(temp)/'result'
        result = subprocess.run([executable, str(ROOT/'review/external_security.py'), '--kind', kind,
                                 '--repo', str(Path.cwd()), '--out', str(out)], env=env,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
        if not (out/'security.json').exists():
            raise RuntimeError('External oracle infrastructure failed: '+result.stderr[-1800:])
        record = json.loads((out/'security.json').read_text())
        if result.returncode not in (0, 1) or not record.get('checks'):
            raise RuntimeError('External oracle did not yield a valid assertion set')
        return record['checks']
