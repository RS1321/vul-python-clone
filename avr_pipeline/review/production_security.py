"""Small, executable security oracles for pinned historical production defects.

Fixture-only inputs; urllib3 uses ephemeral loopback HTTP servers. Requests
proxy handling is inspected before transport. JavaScript runs in a child process.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading


def measure(case, repo):
    repo = repo.resolve()
    checks = []
    def add(name, passed, category='security', detail=None):
        checks.append(dict(name=name, passed=bool(passed), category=category, detail=detail))
    if case == 'requests-proxy':
        sys.path.insert(0, str(repo))
        import requests
        add('clone imported', Path(requests.__file__).resolve().is_relative_to(repo), 'functionality')
        session = requests.Session()
        session.trust_env = False
        for scheme in ('http', 'https'):
            req = requests.Request('GET', scheme + '://fixture.example.invalid/path', headers={'Proxy-Authorization': 'stale-fixture'}).prepare()
            proxies = {scheme: 'http://fixture:password@127.0.0.1:9'}
            result = session.rebuild_proxies(req, proxies)
            add(scheme + ' proxy configuration preserved', result == proxies, 'functionality')
            header = req.headers.get('Proxy-Authorization')
            add(scheme + ' credentials only on correct transport', bool(header) if scheme == 'http' else header is None, detail={'credential_header_present': header is not None})
            req = requests.Request('GET', scheme + '://fixture.example.invalid').prepare()
            session.rebuild_proxies(req, {})
            add(scheme + ' direct request has no proxy credentials', 'Proxy-Authorization' not in req.headers)
        add('normal prepared request retained', requests.Request('POST', 'https://fixture.example.invalid', json={'value': 3}).prepare().body == b'{"value": 3}', 'functionality')
    else:
        sys.path.insert(0, str(repo / 'src'))
        import urllib3
        add('clone imported', Path(urllib3.__file__).resolve().is_relative_to(repo), 'functionality')
        captures = []
        target_port = [None]
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args):
                pass
            def handle_request(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                if self.path.startswith('/redirect'):
                    cross = 'cross' in self.path
                    status = 307 if '307' in self.path else 303
                    location = 'http://127.0.0.1:%d/capture' % target_port[0] if cross else '/capture'
                    self.send_response(status)
                    self.send_header('Location', location)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                else:
                    captures.append(dict(method=self.command, body=body.decode(), cookie=self.headers.get('Cookie'),
                                         authorization=self.headers.get('Authorization'), content_type=self.headers.get('Content-Type'),
                                         length=self.headers.get('Content-Length'), fixture=self.headers.get('X-Fixture')))
                    self.send_response(200)
                    self.send_header('Content-Length', '2')
                    self.end_headers()
                    self.wfile.write(b'OK')
            do_GET = handle_request
            do_POST = handle_request
        servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
        for server in servers:
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
        port = servers[0].server_port
        target_port[0] = servers[1].server_port
        try:
            if case == 'urllib3-cookie':
                from urllib3.util.retry import Retry
                for cross in (False, True):
                    pool = urllib3.PoolManager()
                    response = pool.request('GET', 'http://127.0.0.1:%d/redirect%s' % (port, '-cross' if cross else ''),
                        headers={'Cookie': 'fixture-cookie', 'Authorization': 'fixture-auth', 'X-Fixture': 'keep'}, timeout=3)
                    seen = captures[-1]
                    add('redirect response succeeds ' + str(cross), response.status == 200 and seen['fixture'] == 'keep', 'functionality')
                    add('cookie policy cross=' + str(cross), seen['cookie'] is None if cross else seen['cookie'] == 'fixture-cookie')
                    add('authorization policy cross=' + str(cross), seen['authorization'] is None if cross else seen['authorization'] == 'fixture-auth')
                    pool.clear()
                add('custom redirect policy retained', Retry(remove_headers_on_redirect=[]).remove_headers_on_redirect == frozenset(), 'functionality')
            elif case == 'urllib3-303':
                for direct in (False, True):
                    pool = urllib3.HTTPConnectionPool('127.0.0.1', port) if direct else urllib3.PoolManager()
                    for status in (303, 307):
                        path = '/redirect-' + str(status)
                        url = path if direct else 'http://127.0.0.1:%d%s' % (port, path)
                        response = pool.urlopen('POST', url, body=b'fixture-private-body',
                            headers={'Content-Type': 'application/fixture', 'Content-Length': '20', 'X-Fixture': 'keep'}, timeout=3)
                        seen = captures[-1]
                        label = ('connectionpool' if direct else 'poolmanager') + '-' + str(status)
                        add(label + ' request succeeds', response.status == 200 and seen['fixture'] == 'keep', 'functionality')
                        if status == 303:
                            add(label + ' body removed after GET conversion', seen['method'] == 'GET' and seen['body'] == '', detail=seen)
                            add(label + ' body headers removed', seen['content_type'] is None and seen['length'] in (None, '0'), detail=seen)
                        else:
                            add(label + ' 307 preserves method and body', seen['method'] == 'POST' and seen['body'] == 'fixture-private-body', 'functionality', seen)
                    pool.close() if direct else pool.clear()
            else:
                raise ValueError('Unknown Python case')
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
    return dict(case=case, checks=checks, security_passed=sum(c['passed'] for c in checks if c['category'] == 'security'),
                security_total=sum(c['category'] == 'security' for c in checks),
                functionality_passed=all(c['passed'] for c in checks if c['category'] == 'functionality'),
                passed=all(c['passed'] for c in checks))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = measure(args.case, args.repo)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('case', 'security_passed', 'security_total', 'functionality_passed', 'passed')}))
    raise SystemExit(0 if result['passed'] else 1)
