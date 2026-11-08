"""Recreate a saved model patch from accepted responses, without another API call.

Every applied diff must match its saved finding artifact. Redacted or incompatible
artifacts fail closed; no replacement patch is invented during replay.
"""
import argparse
import difflib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import checked, current, CodePatcher, dump, digest


def replay(run, baseline, out):
    run, baseline, out = Path(run).resolve(), Path(baseline).resolve(), Path(out).resolve()
    m = json.loads((run/'manifest.json').read_text())
    if out.exists() or out.is_relative_to(baseline):
        raise ValueError('Choose a fresh output directory outside the baseline')
    if checked(['git','rev-parse','HEAD'], baseline) != m['source_commit']:
        raise ValueError('Baseline commit differs from saved model input')
    if checked(['git','status','--porcelain','--untracked-files=no'], baseline):
        raise ValueError('Baseline has source edits')
    findings = json.loads((run/'contexts.json').read_text())
    results = {r['finding_id']:r for r in json.loads((run/'results.json').read_text())}
    out.mkdir(parents=True)
    repo = out/'source'
    checked(['git','clone','--local','--no-hardlinks',baseline,repo])
    checked(['git','checkout','--detach',m['source_commit']],repo)
    patcher = CodePatcher(repo)
    verified = []
    for i,f in enumerate(findings,1):
        r = results.get(f['finding_id'],{})
        if not r.get('accepted'):
            continue
        attempts = [a for a in r.get('attempts',[]) if a.get('accepted')]
        if len(attempts) != 1:
            raise ValueError('Expected exactly one accepted response for '+f['finding_id'])
        name = f['sast']['location']['file_path']
        path = (repo/name).resolve()
        if not path.is_relative_to(repo):
            raise ValueError('Saved finding escapes the source tree')
        before = path.read_bytes().decode('utf-8')
        _,details = current(repo,f)
        patch = patcher.parse_fix_response(attempts[0]['response']['content'])
        ok,reason = patcher.apply_fix(name,patch,details)
        if not ok:
            raise ValueError('Saved response cannot be applied: '+reason)
        delta = '\n'.join(difflib.unified_diff(before.splitlines(),path.read_text(encoding='utf-8').splitlines(),lineterm=''))
        expected = (run/f'finding-{i:03d}/patch.diff').read_text(encoding='utf-8')
        if delta.rstrip('\r\n') != expected.rstrip('\r\n'):
            raise ValueError('Replayed diff differs from artifact: '+f['finding_id'])
        verified.append(f['finding_id'])
    (out/'model.patch').write_text(checked(['git','diff','--no-ext-diff'],repo),encoding='utf-8')
    record = {'status':'verified','source_commit':m['source_commit'],'saved_manifest_sha256':digest(run/'manifest.json'),
              'verified_accepted_findings':verified,'model_patch_sha256':digest(out/'model.patch'),
              'scope':'Exact accepted-response/diff replay, not a new model experiment or proof of security.'}
    dump(out/'replay.json',record)
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('run','baseline','out'):
        p.add_argument('--'+name,required=True)
    args = p.parse_args()
    result = replay(args.run,args.baseline,args.out)
    print('Verified accepted patches:',len(result['verified_accepted_findings']))


if __name__ == '__main__':
    main()
