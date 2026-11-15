#!/usr/bin/env python3
"""Prepare deterministic entry guards in an explicitly selected clean checkout.

Does not classify/approve receipts, touch another worktree, publish or run a body.
"""
import ast
from pathlib import Path
import os
import re
import shlex
from urllib.parse import quote

PYTHON = """
# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1
if __name__ == '__main__':
    import pathlib as _vg_pathlib, runpy as _vg_runpy
    _vg_root = next((_p for _p in _vg_pathlib.Path(__file__).resolve().parents if (_p / 'tools/catalogue-publication-gate/guard.py').is_file()), None)
    if _vg_root is None:
        raise SystemExit('CATALOGUE: shared publication preflight missing')
    _vg_runpy.run_path(str(_vg_root / 'tools/catalogue-publication-gate/guard.py'))['entrypoint'](__file__, _vg_root)

"""


# PHP is supported only for permanent retirement of historical CLI publishers.
# This unconditional tombstone also refuses inclusion; no generic PHP build
# admission is implemented. The original body remains in Git for audit.
PHP_RETIRED = "<?php\n// VG-CATALOGUE-PUBLICATION-PREFLIGHT-1\nif (PHP_SAPI === 'cli') { fwrite(STDERR, \"CATALOGUE: historical publisher retired\\n\"); } else { http_response_code(410); }\nexit(78);\n"


def python_offset(text):
    tree = ast.parse(text)
    at = 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
        at = tree.body[0].end_lineno
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == '__future__':
            at = max(at, node.end_lineno)
    lines = text.splitlines(keepends=True)
    while at < len(lines) and (lines[at].startswith('#') or not lines[at].strip()):
        at += 1
    return lines, at


def node_parts(text):
    """Preserve hashbang, comments and directive prologue (e.g. use strict)."""
    offset = text.find('\n') + 1 if text.startswith('#!') else 0
    while offset < len(text):
        match = re.match(r'(?:\s+|//[^\n]*(?:\n|$)|/\*[\s\S]*?\*/)', text[offset:])
        if match:
            offset += match.end()
            continue
        match = re.match(r'''(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")[ \t]*(?:;|(?=\r?\n|$))''', text[offset:])
        if match:
            offset += match.end()
            continue
        break
    return text[:offset], text[offset:]


def shell_entry(path, text):
    first = text.splitlines()[0] if text else ''
    return path.suffix == '.sh' or (not path.suffix and bool(re.fullmatch(r'#!(?:/usr/bin/env (?:bash|sh|zsh)|/(?:usr/)?bin/(?:bash|sh|zsh))', first)))


def wire(root, name):
    path = root / name
    text = path.read_text()
    if 'VG-CATALOGUE-PUBLICATION-PREFLIGHT-1' in text:
        if path.suffix in ['.mjs', '.cjs', '.js']:
            lines = text.splitlines(keepends=True)
            index = next((i for i,line in enumerate(lines[:8]) if line.strip() == '// VG-CATALOGUE-PUBLICATION-PREFLIGHT-1'), None)
            if index is None or index + 1 >= len(lines) or 'preflight.' not in lines[index + 1]:
                return False
            del lines[index:index + 2]
            text = ''.join(lines)
        elif shell_entry(path, text):
            lines = text.splitlines(keepends=True)
            index = next((i for i,line in enumerate(lines[:8]) if line.strip() == '# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1'), None)
            if index is None or index + 2 >= len(lines) or not lines[index + 1].startswith('_vg_root=') or 'catalogue-publication-gate/guard.py' not in lines[index + 2]:
                return False
            del lines[index:index + 3]
            text = ''.join(lines)
        else:
            return False
    if path.suffix == '.php':
        if not text.startswith('<?php\n'):
            raise ValueError('catalogue_php_retirement_header_required')
        new = PHP_RETIRED + text[len('<?php\n'):]
    elif path.suffix == '.py':
        lines, at = python_offset(text)
        new = ''.join(lines[:at]) + PYTHON + ''.join(lines[at:])
        ast.parse(new)
    elif path.suffix in ['.mjs', '.cjs', '.js']:
        esm = path.suffix == '.mjs' or (path.suffix == '.js' and any(line.lstrip().startswith(('import ', 'export ')) for line in text.splitlines()))
        preload = 'preflight.mjs' if esm else 'preflight.cjs'
        relative = os.path.relpath(root / 'tools/catalogue-publication-gate' / preload, path.parent).replace(os.sep, '/')
        if not relative.startswith('.'):
            relative = './' + relative
        statement = ('import ' + repr(relative + '?entry=' + quote(name, safe=''))) if esm else ('require(' + repr(relative) + ')(__filename)')
        header, body = node_parts(text)
        new = header + '// VG-CATALOGUE-PUBLICATION-PREFLIGHT-1\n' + statement + ';\n' + body
    elif shell_entry(path, text):
        relative = os.path.relpath(root, path.parent).replace(os.sep, '/')
        preflight = '\n# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1\n_vg_root="$(CDPATH= cd -- "$(dirname -- "$0")/' + relative + '" && pwd)" || exit 78\npython3 "$_vg_root/tools/catalogue-publication-gate/guard.py" --root "$_vg_root" --registry .catalogue-publication.json --entry ' + shlex.quote(name) + ' >/dev/null || exit 78\n\n'
        first, sep, rest = text.partition('\n')
        new = first + '\n' + preflight + rest if first.startswith('#!') else preflight + text
    else:
        raise ValueError('catalogue_entry_adapter_required:' + name)
    path.write_text(new)
    return True
