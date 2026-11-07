"""Execute the published examples with explicit, bounded context assumptions.

This is reproducible automated checking, not independent human expert review.
The historical review-1 library remains unchanged for existing experiments.
"""
import argparse
from copy import deepcopy
import io
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import textwrap
from types import SimpleNamespace
from unittest.mock import Mock

from flask import Flask, abort, redirect, render_template_string, request
from flask_wtf.csrf import CSRFProtect, generate_csrf
from Crypto.Cipher import AES
from werkzeug.test import Client
from werkzeug.wrappers import Response

ROOT = Path(__file__).resolve().parents[1]


def revised(library):
    library = deepcopy(library)
    library['version'] = 'review-2'
    library['provenance'] = ('Revision following automated behavioral checks. No independent human expert review '
                             'or original expert-review provenance is established.')
    replacements = {
        'CWE-078': "if host not in {'localhost', 'example.com'}:\n    abort(400)\nsubprocess.check_output(['ping', host], shell=False)",
        'CWE-352': "from flask_wtf.csrf import CSRFProtect\napp.config['WTF_CSRF_ENABLED'] = True\nCSRFProtect(app)",
        'CWE-020': "try:\n    age = int(request.args.get('age', ''))\nexcept (TypeError, ValueError):\n    abort(400)\nif not 0 <= age <= 150:\n    abort(400)",
        'CWE-502': "if len(request.data) > 1048576:\n    abort(413)\ndata = json.loads(request.data)\nif not isinstance(data, dict):\n    abort(400)",
        'CWE-776': "if len(xml_data) > 1048576:\n    abort(413)\nfrom defusedxml import ElementTree as safe_xml\ndoc = safe_xml.fromstring(xml_data, forbid_dtd=True, forbid_entities=True)",
        'CWE-400': "with open(filename) as handle:\n    data = handle.read(1048577)\nif len(data) > 1048576:\n    abort(413)"
    }
    assumptions = {
        'CWE-078': 'Illustrative destination allowlist; actual operations, flags, platform and ping timeout must be defined by the application.',
        'CWE-022': 'Allowed root is trusted and stable. Filesystem races require OS-level safe-open controls outside this example.',
        'CWE-352': 'A strong application secret and token-bearing forms/clients are required. Initialize CSRFProtect only once.',
        'CWE-327': 'A securely provisioned valid AES key and nonce lifecycle are application responsibilities.',
        'CWE-502': 'Illustrative dict contract; add a project-specific schema and handle malformed JSON as a client error.',
        'CWE-918': 'Endpoint allowlist and DNS/configuration are trusted. This is not arbitrary-URL validation.',
        'CWE-284': 'Identity is authenticated and owner_id is an authoritative server-side value.',
        'CWE-400': 'Text-character bound in this example; use binary mode if the contract is a byte bound.'
    }
    for entry in library['entries']:
        if entry['cwe'] in replacements:
            entry['after'] = replacements[entry['cwe']]
        entry['assumptions'] = assumptions.get(entry['cwe'], 'Illustrative fragment; imports, error policy and application contract must be supplied.')
    return library


def execute(entry, values, tail=''):
    env = dict(values)
    code = 'def example():\n' + textwrap.indent(entry['after'] + '\n' + tail, '    ')
    exec(compile(code, '<guidance-example>', 'exec'), env)
    return env['example']()


def verify(entry, workspace):
    cwe = int(entry['cwe'].split('-')[1])
    app = Flask('vet-guidance')
    app.secret_key = 'local-automated-fixture-only'
    env = dict(app=app, abort=abort, redirect=redirect, request=request,
               render_template_string=render_template_string)
    checks = []
    def record(name, passed):
        checks.append({'name': name, 'passed': bool(passed)})
    def run(values=None, tail=''):
        return execute(entry, dict(env, **(values or {})), tail)
    with app.test_request_context('/'):
        if cwe == 78:
            command = Mock(return_value=b'ok')
            run({'host': 'localhost', 'subprocess': SimpleNamespace(check_output=command)})
            record('argument list; shell disabled', command.call_args.args == (['ping', 'localhost'],) and command.call_args.kwargs.get('shell') is False)
        elif cwe == 89:
            connection = sqlite3.connect(':memory:')
            connection.execute('CREATE TABLE users (name TEXT)')
            connection.execute('INSERT INTO users VALUES (?)', ("O'Connor",))
            cursor = connection.cursor()
            run({'cursor': cursor, 'name': "O'Connor"})
            record('parameter binding preserves literal name', cursor.fetchall() == [("O'Connor",)])
            connection.close()
        elif cwe in (79, 74):
            rendered = run({'name': '<em>label</em>', 'user_text': 'plain {{ content }}'})
            record('literal data rendered', '&lt;em&gt;' in rendered if cwe == 79 else 'plain {{ content }}' in rendered)
        elif cwe == 22:
            file = workspace / 'inside.txt'
            file.write_text('fixture')
            sent = Mock(return_value='sent')
            value = run({'root': workspace, 'filename': 'inside.txt', 'send_file': sent})
            record('resolved local file retained', value == 'sent' and sent.call_args.args[0] == file.resolve())
        elif cwe == 215:
            stub = SimpleNamespace(run=Mock())
            run({'app': stub})
            record('debug explicitly disabled', stub.run.call_args.kwargs == {'debug': False})
        elif cwe == 209:
            stub = SimpleNamespace(logger=SimpleNamespace(exception=Mock()))
            value = run({'app': stub, 'error': ValueError('diagnostic fixture')})
            record('generic client error and server log', value == ('Internal server error', 500) and stub.logger.exception.called)
        elif cwe == 601:
            value = run()
            record('unknown redirect choice uses local fallback', value.location == '/')
        elif cwe == 352:
            # A configuration flag alone does not initialize Flask-WTF protection.
            app.config['WTF_CSRF_ENABLED'] = False
            run()
            app.add_url_rule('/form', 'form', lambda: 'ok', methods=['POST'])
            record('missing form token rejected', Client(app, Response).post('/form').status_code == 400)
        elif cwe == 20:
            for age, expected in [('42', None), ('200', 400), ('not-an-age', 400)]:
                with app.test_request_context('/?age=' + age):
                    try:
                        run()
                        observed = None
                    except Exception as exc:
                        observed = getattr(exc, 'code', type(exc).__name__)
                    record('age boundary ' + age, observed == expected)
        elif cwe == 327:
            key, data = secrets.token_bytes(32), b'ordinary message'
            nonce, ciphertext, tag = run({'AES': AES, 'key': key, 'data': data}, 'return result')
            decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            record('authenticated encryption round trip', decipher.decrypt_and_verify(ciphertext, tag) == data)
        elif cwe == 502:
            value = run({'json': json, 'request': SimpleNamespace(data=b'{"name":"sample"}')}, 'return data')
            record('data-only object decoding', value == {'name': 'sample'})
        elif cwe == 918:
            get = Mock(return_value=SimpleNamespace(status_code=200))
            with app.test_request_context('/?service=status'):
                run({'requests': SimpleNamespace(get=get)})
            record('fixed endpoint with bounded request policy', get.call_args.args == ('https://api.example.com/status',) and get.call_args.kwargs == {'allow_redirects': False, 'timeout': 5})
        elif cwe in (611, 776):
            document = run({'xml_data': b'<message>hello</message>'}, 'return doc')
            record('ordinary XML parsing', document.tag == 'message' and document.text == 'hello')
        elif cwe == 284:
            account = SimpleNamespace(owner_id=7, to_dict=lambda: {'id': 7})
            value = run({'account': account, 'current_user': SimpleNamespace(id=7)})
            record('owner retains ordinary access', value == {'id': 7})
            try:
                run({'account': account, 'current_user': SimpleNamespace(id=8)})
                record('nonowner rejected', False)
            except Exception as exc:
                record('nonowner rejected', getattr(exc, 'code', None) == 403)
        elif cwe == 400:
            handle = io.StringIO('ordinary file')
            value = run({'filename': 'fixture', 'open': lambda _: handle}, 'return data')
            record('read result and closed handle', value == 'ordinary file' and handle.closed)
        elif cwe == 330:
            token = run({'secrets': secrets}, 'return token')
            record('cryptographic API produces a token', isinstance(token, str) and len(token) >= 40)
        else:
            raise ValueError('Missing example check')
    return {'cwe': entry['cwe'], 'checks': checks, 'passed': all(c['passed'] for c in checks),
            'scope': 'Bounded automated checks, not proof of general correctness', 'source': entry['source']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT / 'continuation/results/guidance-vetting.json')
    args = parser.parse_args()
    original = json.loads((ROOT / 'llm/guidance_library.json').read_text())
    updated = revised(original)
    (ROOT / 'llm/guidance_library.review-2.json').write_text(json.dumps(updated, indent=2), encoding='utf-8')
    results = []
    with tempfile.TemporaryDirectory(dir=ROOT / '.review-work') as folder:
        for library in (original, updated):
            rows = [verify(entry, Path(folder)) for entry in library['entries']]
            results.append({'version': library['version'], 'entries': rows,
                            'passing_entries': sum(row['passed'] for row in rows),
                            'independent_human_review': False})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps([{'version': r['version'], 'passing_entries': r['passing_entries'], 'total': len(r['entries'])} for r in results]))


if __name__ == '__main__':
    main()
