"""Portable package-version snapshot without package URLs or credentials."""
import argparse
from importlib import metadata
from pathlib import Path
import platform
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--out', required=True, type=Path)
args = parser.parse_args()
args.out.parent.mkdir(parents=True, exist_ok=True)
versions = sorted({f'{d.metadata["Name"]}=={d.version}' for d in metadata.distributions()}, key=str.lower)
args.out.write_text(f'# Python {platform.python_version()}; {platform.system()}\n' + '\n'.join(versions) + '\n', encoding='utf-8')
print('Recorded package versions:', len(versions))
