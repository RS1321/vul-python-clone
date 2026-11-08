"""Create a checksummed source/evidence archive from a clean, exact Git commit."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=ROOT/'avr_pipeline/.review-work/release')
    args = p.parse_args()
    def git(*parts):
        return subprocess.check_output(['git',*parts],cwd=ROOT,text=True,encoding='utf-8').strip()
    if git('status','--porcelain'):
        raise ValueError('Commit the complete delivery before making an archive')
    sha = git('rev-parse','HEAD')
    args.out.mkdir(parents=True,exist_ok=True)
    path = args.out/('avr-review2-'+sha[:12]+'.zip')
    if path.exists():
        raise ValueError('Archive already exists; preserve the original')
    subprocess.run(['git','archive','--format=zip','--output='+str(path.resolve()),sha],cwd=ROOT,check=True)
    record = {'commit':sha,'archive':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
              'scope':'Git-tracked source and evidence; credentials, runtime clones, model weights and scanner binaries excluded.',
              'doi':None,'zenodo_status':'not published'}
    (args.out/'release-manifest.json').write_text(json.dumps(record,indent=2))
    print(json.dumps(record,indent=2))


if __name__ == '__main__':
    main()
