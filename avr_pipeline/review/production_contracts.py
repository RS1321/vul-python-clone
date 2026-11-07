"""Small production-library contract checks, with no external network requests.

These are bounded configuration/API checks, not a full vulnerability oracle.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def check(dataset, repo):
    if dataset == 'urllib3':
        code = '''import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'src'))
import urllib3
from urllib3.util.retry import Retry
checks = {
 'clone_imported': Path(urllib3.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve()),
 'cookie_default_policy': 'cookie' in Retry().remove_headers_on_redirect,
 'authorization_default_policy': 'authorization' in Retry().remove_headers_on_redirect,
 'custom_empty_policy_preserved': Retry(remove_headers_on_redirect=[]).remove_headers_on_redirect == frozenset(),
 'custom_header_case_normalized': Retry(remove_headers_on_redirect=['X-Private']).remove_headers_on_redirect == frozenset(['x-private']),
 'retry_copy_retains_policy': Retry().new(total=1).remove_headers_on_redirect == Retry().remove_headers_on_redirect,
 'safe_method_contract': Retry().is_retry('GET', 503, has_retry_after=True),
 'ordinary_nonretry_status': not Retry().is_retry('GET', 200)
}
print(json.dumps({'checks':checks,'passed':all(checks.values()),'import_path':urllib3.__file__}))
'''
        args = [sys.executable, '-B', '-c', code, str(repo)]
    else:
        code = """const assert = require('assert');
const parse = require(process.argv[1] + '/index.js');
let count=0;
function check(f){f(); count++;}
check(()=>assert.deepStrictEqual(parse(['--name','sample']), {_:[],name:'sample'}));
check(()=>assert.strictEqual(parse(['--count','3']).count,3));
check(()=>assert.strictEqual(parse(['--no-color']).color,false));
check(()=>assert.strictEqual(parse(['--group.name','sample']).group.name,'sample'));
check(()=>assert.strictEqual(parse(['-v'],{alias:{v:'verbose'}}).verbose,true));
check(()=>assert.deepStrictEqual(parse(['--x','1','--x','2']).x,[1,2]));
check(()=>assert.deepStrictEqual(parse(['--','plain'])._,['plain']));
check(()=>assert.strictEqual(parse([],{default:{name:'sample'}}).name,'sample'));
console.log(JSON.stringify({checks:count,passed:true}));
"""
        args = ['node', '-e', code, str(repo)]
    import os, re
    env = {k: v for k, v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
    p = subprocess.run(args, capture_output=True, text=True, timeout=60, env=env)
    try:
        result = json.loads(p.stdout)
    except ValueError:
        result = {'passed': False, 'error': p.stderr[-2000:]}
    result['returncode'] = p.returncode
    result['scope'] = 'bounded API/configuration contract checks; no full security fix-rate claim'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', choices=['urllib3', 'minimist'], required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.dataset, args.repo.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
