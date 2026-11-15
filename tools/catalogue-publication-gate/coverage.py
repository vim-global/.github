#!/usr/bin/env python3
"""Read-only detection of missing publisher registration and entrypoint wiring."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import runpy
import shlex
from urllib.parse import quote

MARKER = 'VG-CATALOGUE-PUBLICATION-PREFLIGHT-1'
EXTENSIONS = {'.py', '.sh', '.mjs', '.cjs', '.js', '.ts', '.tsx', '.yml', '.yaml', '.service', '.timer', '.php', '.rb', '.pl', '.go', '.rs', '.ps1', '.cmd', '.bat'}
NAMES = re.compile(r'(release|publish|deploy|install|build|upload|package)', re.I)
OPERATIONS = re.compile(r'\b(ssh|rsync|sftp|scp|paramiko|ftplib)\b|deploy-pages|docker\s+push|curl[^\n]*(?:--upload-file|\s-T\s)|systemctl[^\n]*(?:reload|restart)|(?:writeFileSync|write_text|write_bytes|file_put_contents|shutil\.copy|\.mkdir\()')
EXCLUDED = re.compile(r'(^|/)(node_modules|vendor|backups|proofs|fixtures|\.agents|skills|tests?)/|(^|/)(test_[^/]*|[^/]*\.test\.[^/]*)$')


def wired_first(root, name, text):
    if MARKER not in text:
        return False
    if name.endswith('.php'):
        return text.startswith(runpy.run_path(str(Path(__file__).with_name('wire.py')))['PHP_RETIRED'])
    if name.endswith('.py'):
        expected = ast.parse(runpy.run_path(str(Path(__file__).with_name('wire.py')))['PYTHON']).body[0]
        try:
            nodes = ast.parse(text).body
        except SyntaxError:
            return False
        if nodes and isinstance(nodes[0], ast.Expr) and isinstance(nodes[0].value, ast.Constant) and isinstance(nodes[0].value.value, str):
            nodes = nodes[1:]
        while nodes and isinstance(nodes[0], ast.ImportFrom) and nodes[0].module == '__future__':
            nodes = nodes[1:]
        return bool(nodes) and ast.dump(nodes[0]) == ast.dump(expected)
    if name.endswith(('.mjs', '.cjs', '.js')):
        import os
        esm = name.endswith('.mjs') or (name.endswith('.js') and any(line.lstrip().startswith(('import ', 'export ')) for line in text.splitlines()))
        suffix = '.mjs' if esm else '.cjs'
        relative = os.path.relpath(root / ('tools/catalogue-publication-gate/preflight' + suffix), (root / name).parent).replace(os.sep, '/')
        if not relative.startswith('.'):
            relative = './' + relative
        _, body = runpy.run_path(str(Path(__file__).with_name('wire.py')))['node_parts'](text)
        lines = body.splitlines()
        wanted = ('import ' + repr(relative + '?entry=' + quote(name, safe=''))) if esm else ('require(' + repr(relative) + ')(__filename)')
        return bool(lines) and lines[0].strip() == wanted + ';'
    if name.endswith('.sh'):
        source = text.splitlines()
        first = 1 if source and source[0].startswith('#!') else 0
        # Pure reconstruction, no execution or temporary filesystem write.
        import os
        relative = os.path.relpath(root, (root / name).parent).replace(os.sep, '/')
        prefix = '\n# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1\n_vg_root="$(CDPATH= cd -- "$(dirname -- "$0")/' + relative + '" && pwd)" || exit 78\npython3 "$_vg_root/tools/catalogue-publication-gate/guard.py" --root "$_vg_root" --registry .catalogue-publication.json --entry ' + shlex.quote(name) + ' >/dev/null || exit 78\n'
        return '\n'.join(source[first:]).startswith(prefix)
    return False


def candidates(root):
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    result = {}
    for name in names:
        path = root / name
        named_entry = path.name in ['Makefile', 'Dockerfile', 'Procfile'] or path.name.startswith('Dockerfile.')
        extensionless = not path.suffix and path.is_file() and not path.is_symlink() and path.stat().st_size <= 1000000
        if (path.suffix.lower() not in EXTENSIONS and not named_entry and not extensionless) or name.startswith('tools/catalogue-publication-gate/'):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        text = path.read_text(errors='replace')
        if extensionless and not named_entry and not text.startswith('#!'):
            continue
        # Keep path-name detection independent of body detection: deleting a
        # characteristic command must not remove an existing release entry.
        if EXCLUDED.search(name):
            # Test/fixture/backup folders are not an unconditional bypass: a
            # named publisher or real transfer primitive is still a candidate.
            if not re.match(r'^(release|deploy|publish|install|upload)[-_\.]', path.name, re.I) and not re.search(r'\b(rsync|sftp|scp|paramiko|ftplib)\b|deploy-pages|docker\s+push', text):
                continue
        if named_entry or extensionless or path.suffix in ['.service', '.timer'] or NAMES.search(path.name) or OPERATIONS.search(text):
            result[name] = text
    return result


def audit(root):
    registry = json.loads((root / '.catalogue-publication.json').read_text())
    if registry.get('version') != 1:
        raise ValueError('catalogue_registry_version')
    found = candidates(root)
    records = registry.get('publishers', {})
    failures = []
    for name, text in found.items():
        record = records.get(name, {})
        status = record.get('status')
        if status not in ['retired', 'guarded', 'no-ui', 'exempt']:
            failures.append(name + ':unmapped')
        elif status == 'exempt':
            review = record.get('controller_review', {})
            if not isinstance(review, dict) or review.get('decision') != 'approved' or not review.get('review_id') or not review.get('reviewer') or review.get('source_sha256') != record.get('sha256') or not record.get('reason') or hashlib.sha256(text.encode()).hexdigest() != record.get('sha256'):
                failures.append(name + ':no-ui-classification-stale')
            if record.get('entry_kind') == 'cli' and not wired_first(root, name, text):
                failures.append(name + ':exempt-cli-preflight-missing')
        elif not wired_first(root, name, text):
            failures.append(name + ':preflight-missing')
    # Explicit entries are checked even if a future scanner heuristic misses them.
    for name, record in records.items():
        if name not in found:
            path = root / name
            if not path.is_file() or path.is_symlink():
                failures.append(name + ':registered-entry-missing')
            elif record.get('status') == 'exempt':
                review = record.get('controller_review', {})
                if not isinstance(review, dict) or review.get('decision') != 'approved' or not review.get('review_id') or not review.get('reviewer') or review.get('source_sha256') != record.get('sha256') or not record.get('reason') or hashlib.sha256(path.read_bytes()).hexdigest() != record.get('sha256'):
                    failures.append(name + ':no-ui-classification-stale')
                if record.get('entry_kind') == 'cli' and not wired_first(root, name, path.read_text(errors='replace')):
                    failures.append(name + ':exempt-cli-preflight-missing')
            elif not wired_first(root, name, path.read_text(errors='replace')):
                failures.append(name + ':preflight-missing')
    return {'checked': not failures, 'candidate_count': len(found), 'registered_count': len(records), 'failures': failures}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[2]))
    args = parser.parse_args()
    try:
        result = audit(Path(args.root))
        print(json.dumps(result, sort_keys=True))
        sys.exit(0 if result['checked'] else 1)
    except (OSError, ValueError, KeyError):
        print('{"checked":false,"error":"catalogue_registry_required"}')
        sys.exit(1)
