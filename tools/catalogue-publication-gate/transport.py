"""Shared SSH transport lease: no unchecked mutating command or mutable stdin.

Does not open a connection. The existing authorized consumer retains its SSH
binding and calls subprocess only inside this context. Not an access grant.
"""
from contextlib import contextmanager
from collections import namedtuple
import hashlib
import json
from pathlib import Path
import re
import runpy
import shlex
import tempfile
import subprocess


ReviewedTransport = namedtuple('ReviewedTransport', ['command', 'stdin'])

def read_only_shell(command):
    if not isinstance(command, str) or re.search(r'[;&|<>`$\n\r\\]', command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if not words or words[0] not in ['cat', 'sha256sum', 'stat', 'ls', 'pwd']:
        return False
    if words[0] == 'pwd':
        return len(words) == 1
    paths = [word for word in words[1:] if not word.startswith('-')]
    return bool(paths) and all(re.fullmatch(r'[A-Za-z0-9_./:@%+=, -]+', word) for word in words) and all((word == 'public_html' or word.startswith('public_html/')) and '..' not in Path(word).parts and not any(part.startswith('.') or part.lower() in ['wp-config.php', 'config.php'] for part in Path(word).parts) for word in paths)


@contextmanager
def transport(command, caller, root, stdin=None, input_data=None, encoding='utf-8'):
    if stdin is None and input_data is None and read_only_shell(command):
        yield ReviewedTransport(command, None)
        return
    if not isinstance(command, str) or (stdin is not None and input_data is not None):
        raise SystemExit('CATALOGUE: unsupported transport input')
    guard = runpy.run_path(str(Path(__file__).with_name('guard.py')))
    root = Path(root).resolve(strict=True)
    result = guard['entrypoint'](caller, root)
    if result.get('scope') != 'publication':
        raise SystemExit('CATALOGUE: creation or exemption does not authorize remote mutation')
    entry = Path(caller).resolve(strict=True).relative_to(root).as_posix()
    registry = json.loads(guard['safe_file'](root, '.catalogue-publication.json').read_text())
    record = registry['publishers'][entry]
    if record.get('receipt', {}).get('sha256') != result.get('receipt_sha256'):
        raise SystemExit('CATALOGUE: transport receipt changed')
    receipt = json.loads(guard['bound_document'](root, record['receipt']))
    command_sha = hashlib.sha256(command.encode('utf-8')).hexdigest()
    stream = None
    try:
        payload_sha = None
        if stdin is not None or input_data is not None:
            stream = tempfile.TemporaryFile(mode='w+b')
            digest = hashlib.sha256()
            if input_data is not None:
                chunks = [input_data.encode(encoding) if isinstance(input_data, str) else input_data]
            else:
                chunks = iter(lambda: stdin.read(65536), b'')
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise SystemExit('CATALOGUE: binary frozen transport input required')
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            stream.seek(0)
            payload_sha = digest.hexdigest()
        approved = receipt.get('transport', [])
        if {'command_sha256': command_sha, 'stdin_sha256': payload_sha} not in approved:
            raise SystemExit('CATALOGUE: command or frozen payload was not independently reviewed')
        # Recheck after capture, immediately before the consumer starts SSH.
        current = guard['entrypoint'](caller, root)
        if current.get('receipt_sha256') != result['receipt_sha256'] or current.get('scope') != 'publication':
            raise SystemExit('CATALOGUE: release evidence changed at transport use')
        yield ReviewedTransport(command, stream)
    finally:
        if stream is not None:
            stream.close()


def run_checked(prefix, command, caller, root, **kwargs):
    """Existing consumer supplies its unchanged authenticated SSH prefix.

    Execute exactly the command/stream returned by the verified lease. This is
    not an alternate credential source or a grant of remote access.
    """
    if not isinstance(prefix, list) or not prefix or not all(isinstance(x, str) for x in prefix) or kwargs.get('shell') or kwargs.get('executable'):
        raise SystemExit('CATALOGUE: direct argument-vector consumer required')
    original_stdin = kwargs.pop('stdin', None)
    original_input = kwargs.pop('input', None)
    with transport(command, caller, root, stdin=original_stdin, input_data=original_input, encoding=kwargs.get('encoding') or 'utf-8') as approved:
        if approved.stdin is not None:
            kwargs['stdin'] = approved.stdin
        return subprocess.run(prefix + [approved.command], **kwargs)
