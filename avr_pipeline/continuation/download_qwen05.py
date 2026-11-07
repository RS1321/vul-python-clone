"""Fetch one official free local-model file and verify its published LFS digest."""
import hashlib
import json
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
repo = 'Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF'
filename = 'qwen2.5-coder-0.5b-instruct-q4_k_m.gguf'
response = requests.get('https://huggingface.co/api/models/' + repo, params={'blobs': 'true'}, timeout=30)
response.raise_for_status()
metadata = response.json()
file = next(s for s in metadata['siblings'] if s['rfilename'] == filename)
expected = file['lfs']['sha256']
folder = ROOT / '.review-work/local-qwen05'
folder.mkdir(parents=True, exist_ok=True)
target = folder / 'model.gguf'
if not target.exists():
    temporary = folder / 'model.download'
    with requests.get('https://huggingface.co/' + repo + '/resolve/' + metadata['sha'] + '/' + filename,
                      stream=True, timeout=(30, 60)) as download:
        download.raise_for_status()
        with temporary.open('wb') as handle:
            for chunk in download.iter_content(1024 * 1024):
                handle.write(chunk)
    actual = hashlib.file_digest(temporary.open('rb'), 'sha256').hexdigest()
    if actual != expected:
        raise RuntimeError('Model digest mismatch; downloaded file is not used')
    temporary.replace(target)
with target.open('rb') as handle:
    actual = hashlib.file_digest(handle, 'sha256').hexdigest()
if actual != expected:
    raise RuntimeError('Model digest mismatch')
provenance = {'model_source': repo, 'revision': metadata['sha'], 'file': filename,
              'sha256': actual, 'bytes': target.stat().st_size,
              'reason': 'Supplemental local candidate after repeated hosted-service interruptions; selected before observing patch outcomes.'}
(ROOT / 'continuation/results/local-qwen05-provenance.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')
print('Verified official local model:', repo, target.stat().st_size)
