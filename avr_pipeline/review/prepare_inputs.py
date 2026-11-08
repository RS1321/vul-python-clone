"""Create separate pinned public benchmark clones without resetting any checkout."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True, encoding='utf-8').strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--datasets', nargs='+', choices=['synthetic', 'pygoat', 'vampi', 'flask-webgoat'], default=['synthetic', 'pygoat', 'vampi', 'flask-webgoat'])
    parser.add_argument('--source-cache', type=Path, help='Optional directory of already downloaded pristine dataset clones')
    args = parser.parse_args()
    for name in args.datasets:
        record = json.loads((ROOT / f'review_results/baseline-{name}/dataset-manifest.json').read_text())
        destination = ROOT / 'benchmarks' / name
        if destination.exists():
            if not (destination / '.git').exists() or git(destination, 'rev-parse', 'HEAD') != record['source_commit']:
                raise ValueError('Existing checkout differs; preserve it and select a separate location')
            if git(destination, 'status', '--porcelain', '--untracked-files=no'):
                raise ValueError('Existing checkout has source edits; refusing to reset')
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            cached = args.source_cache / name if args.source_cache else None
            source = str(cached) if cached and (cached / '.git').exists() else record['source_url']
            subprocess.run(['git', 'clone', '--no-hardlinks', source, str(destination)], check=True)
            subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', record['source_commit']], check=True)
            subprocess.run(['git', '-C', str(destination), 'remote', 'set-url', 'origin', record['source_url']], check=True)
        print(name, record['source_commit'])


if __name__ == '__main__':
    main()
