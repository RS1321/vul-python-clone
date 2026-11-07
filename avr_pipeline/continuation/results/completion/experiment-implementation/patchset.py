"""Verified, coordinated Python/JavaScript edits with rollback on failed checks.

Every edit is tied to a file digest and one exact fragment. Validation runs after
all files are written, so it can check contracts between modules. This is process
rollback, not an assertion that several filesystem writes are crash-atomic.
"""
import ast
import hashlib
import os
from pathlib import Path
import tempfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def syntax_check(path, data):
    text = data.decode('utf-8')
    if path.suffix == '.py':
        ast.parse(text, filename=str(path))
        compile(text, str(path), 'exec')
    elif path.suffix == '.js':
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        parser = Parser(Language(tree_sitter_javascript.language()))
        if parser.parse(data).root_node.has_error:
            raise ValueError('JavaScript syntax check failed')
    else:
        raise ValueError('Supported source extensions: .py and .js')


def write_bytes(path, data):
    mode = path.stat().st_mode
    handle, temporary = tempfile.mkstemp(prefix='.avr-patch-', dir=path.parent)
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_patchset(repo, edits, validate, max_changed_lines=100):
    """Apply digest-bound edits; retain them only if validate(repo) passes.

    Edits have path, sha256, before and after fields. Digests always refer to the
    initial file, including when several fragments in one file are edited.
    A caller must supply project checks; syntax alone cannot accept a patchset.
    """
    import difflib
    root = Path(repo).resolve(strict=True)
    original, staged = {}, {}
    result = {'accepted': False, 'files': [], 'changed_lines': 0,
              'validation': None, 'rolled_back': False}
    written = []
    try:
        if not callable(validate):
            raise ValueError('Project validation is required')
        if not isinstance(edits, list) or not edits or len(edits) > 20:
            raise ValueError('Expected between 1 and 20 edits')
        for edit in edits:
            relative = Path(edit['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('Patch path must be relative and contained')
            path = (root / relative).resolve(strict=True)
            if not path.is_relative_to(root) or any(p.lower() == '.git' for p in path.relative_to(root).parts):
                raise ValueError('Patch path escapes allowed source')
            if not path.is_file() or path.suffix not in ('.py', '.js'):
                raise ValueError('Unsupported source file')
            if path not in original:
                original[path] = path.read_bytes()
                staged[path] = original[path].decode('utf-8')
            if sha256(original[path]) != edit['sha256']:
                raise ValueError('File digest is stale')
            before, after = edit['before'], edit['after']
            if not isinstance(before, str) or not isinstance(after, str) or not before or before == after:
                raise ValueError('Expected a nonempty changed fragment')
            if staged[path].count(before) != 1:
                raise ValueError('Fragment is absent or ambiguous')
            staged[path] = staged[path].replace(before, after, 1)
        for path, text in staged.items():
            syntax_check(path, text.encode('utf-8'))
            diff = list(difflib.ndiff(original[path].decode('utf-8').splitlines(), text.splitlines()))
            result['changed_lines'] += sum(line.startswith(('+ ', '- ')) for line in diff)
        if not 0 < result['changed_lines'] <= max_changed_lines:
            raise ValueError('Patchset exceeds its change budget')
        for path in staged:
            if path.read_bytes() != original[path]:
                raise ValueError('Source changed while preparing patchset')
        for path, text in staged.items():
            # Include the current path in rollback even if its write fails.
            written.append(path)
            write_bytes(path, text.encode('utf-8'))
        result['validation'] = validate(root)
        if not isinstance(result['validation'], dict) or result['validation'].get('passed') is not True:
            raise ValueError('Project checks rejected the coordinated change')
        if any(p.read_bytes() != staged[p].encode('utf-8') for p in staged):
            raise ValueError('Project validation modified a proposed source file')
        result['files'] = [{'path': str(p.relative_to(root)),
                            'before_sha256': sha256(original[p]),
                            'after_sha256': sha256(staged[p].encode('utf-8'))} for p in staged]
        result['accepted'] = True
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, UnicodeError, ImportError) as exc:
        result['error'] = str(exc)
    finally:
        if written and not result['accepted']:
            for path in reversed(written):
                write_bytes(path, original[path])
            result['rolled_back'] = True
    return result
