"""Build a source/results ZIP excluding credentials, caches and scanner databases."""
import os
import re
from pathlib import Path
import zipfile

root=Path(__file__).resolve().parents[1]
export=root.parent/'vul-python-clone/avr_pipeline'
package_root=export if (export/'EXPORT_MANIFEST.json').exists() else root
destination=root.parent/'AVR_Reviewer_Revision.zip'
pending=destination.with_suffix('.zip.tmp')
excluded={'.git','.venv','.review-work','benchmarks','__pycache__','.pytest_cache','codeql-db','zap-home','target-state',
          'source','synthetic-A-checkpoint-source'}
secrets=[v for k,v in os.environ.items() if k in ('OPENAI_API_KEY','GEMINI_API_KEY','OPENROUTER_API_KEY') and v]
extensions={'.py','.js','.json','.md','.txt','.log','.xml','.diff','.patch','.yaml','.yml','.sarif','.toml','.ini','.ps1','.csv','.example','.tap'}
redacted=0
with zipfile.ZipFile(pending,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for base,dirs,files in os.walk(package_root):
        dirs[:]=[d for d in dirs if d not in excluded]
        for name in files:
            path=Path(base)/name
            if name=='.env' or path.suffix in ('.db','.pyc','.lock') or name.startswith('.coverage'):
                continue
            if path.suffix not in extensions and name not in ('.gitignore','.gitattributes','.coveragerc','.python-version','LICENSE','NOTICE','COPYING'):
                continue
            data=path.read_bytes()
            for secret in secrets:
                needle=secret.encode('utf-8')
                if needle in data:
                    data=data.replace(needle,b'<redacted-credential>')
                    redacted+=1
            data,count=re.subn(rb'AIza[0-9A-Za-z_-]{30,}|sk-(?:proj-|or-v1-)?[0-9A-Za-z_-]{30,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}',b'REDACTED_BENCHMARK_CREDENTIAL',data)
            redacted+=bool(count)
            archive.writestr('AVR-System-review/'+str(path.relative_to(package_root)).replace('\\','/'),data)
with zipfile.ZipFile(pending) as archive:
    damaged=archive.testzip()
    if damaged:
        raise RuntimeError(f'Archive verification failed at {damaged}')
pending.replace(destination)
print(f'Created {destination}; credential-containing entries sanitised: {redacted}')
