#!/usr/bin/env python3
"""One fail-closed publication preflight. Evidence binding, not visual acceptance.

No network, writes, receipt generation or approval generation. No shell eval.
Administrative access is outside this guard's security boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

VERSION = 1
SHA = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")


class Refused(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_file(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:
        raise Refused('catalogue_unsafe_path')
    root = root.resolve(strict=True)
    path = root
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise Refused('catalogue_symlink_forbidden')
    if not path.is_file() or root not in path.resolve().parents:
        raise Refused('catalogue_file_missing')
    return path


def inventory(root, scopes):
    result = {}
    if not isinstance(scopes, list) or not scopes:
        raise Refused('catalogue_scopes_required')
    for scope in scopes:
        if not isinstance(scope, str) or not scope or Path(scope).is_absolute() or '..' in Path(scope).parts:
            raise Refused('catalogue_unsafe_scope')
        target = root / scope
        if target.is_symlink() or not target.exists():
            raise Refused('catalogue_scope_missing')
        # Check every parent too, including a symlink leading into a directory.
        probe = root
        for part in Path(scope).parts:
            probe = probe / part
            if probe.is_symlink():
                raise Refused('catalogue_symlink_forbidden')
        files = [target] if target.is_file() else sorted(target.rglob('*'))
        for path in files:
            if path.is_symlink():
                raise Refused('catalogue_symlink_forbidden')
            if path.is_file():
                name = path.relative_to(root).as_posix()
                result[name] = digest(safe_file(root, name).read_bytes())
    if not result:
        raise Refused('catalogue_empty_scope')
    return dict(sorted(result.items()))


def bound_document(root, spec):
    if not isinstance(spec, dict) or set(spec) != {'path', 'sha256'} or not SHA.fullmatch(str(spec['sha256'])):
        raise Refused('catalogue_document_binding_required')
    data = safe_file(root, spec['path']).read_bytes()
    if digest(data) != spec['sha256']:
        raise Refused('catalogue_document_changed')
    return data


def verify_receipt(root, entry, record, artifact_root=None, ui=True):
    """Validate a registry-pinned receipt for the exact registered source scope."""
    receipt = json.loads(bound_document(root, record['receipt']))
    wanted_status = 'catalogue-compared-before-implementation' if ui else 'no-ui-scope-reviewed'
    if receipt.get('version') != VERSION or receipt.get('status') != wanted_status:
        raise Refused('catalogue_comparison_required')
    if receipt.get('phase') != record.get('phase'):
        raise Refused('catalogue_build_is_not_publication_approval')
    if receipt.get('publisher') != entry or not COMMIT.fullmatch(str(receipt.get('source_commit', ''))):
        raise Refused('catalogue_source_binding_required')
    if receipt.get('source_scopes') != record['source_scopes']:
        raise Refused('catalogue_scope_changed')
    actual = inventory(root, record['source_scopes'])
    if entry not in actual or any(name not in actual for name in record.get('required_source_files', [])):
        raise Refused('catalogue_publisher_source_required')
    if actual != receipt.get('source_files'):
        raise Refused('catalogue_source_changed')
    # Independently reconstruct source commit scope, rather than trust a label.
    for name, expected in actual.items():
        command = ['git', '-C', str(root), 'show', receipt['source_commit'] + ':' + name]
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode or digest(result.stdout) != expected:
            raise Refused('catalogue_source_commit_mismatch')
    artifact_files = {}
    if record.get('phase') == 'publish':
        issued, expires = receipt.get('issued_at'), receipt.get('expires_at')
        if any(isinstance(x, bool) or not isinstance(x, (float, int)) for x in [issued, expires]) or not issued <= time.time() < expires <= issued + 900:
            raise Refused('catalogue_fresh_release_admission_required')
        if artifact_root is None or receipt.get('artifact_scopes') != record.get('artifact_scopes'):
            raise Refused('catalogue_release_artifact_required')
        artifact_files = inventory(Path(artifact_root).resolve(strict=True), record['artifact_scopes'])
        if artifact_files != receipt.get('artifact_files'):
            raise Refused('catalogue_release_artifact_changed')
    elif record.get('phase') != 'build':
        raise Refused('catalogue_phase_required')
    if ui:
        passport = receipt.get('passport', {})
        if not passport.get('component') or not passport.get('version'):
            raise Refused('catalogue_passport_required')
        bound_document(root, passport.get('document'))
        # Use a frozen pre-implementation entry/excerpt linked to the canonical
        # project journal, not a second mutable UI-standard document.
        bound_document(root, receipt.get('journal'))
        if record.get('phase') == 'publish':
            phone = json.loads(bound_document(root, receipt.get('phone_proof')))
            if phone.get('viewport') != {'width': 393, 'height': 852} or phone.get('overflow') is not False or not phone.get('states_checked'):
                raise Refused('catalogue_phone_proof_required')
    elif not receipt.get('no_ui_reason'):
        raise Refused('catalogue_no_ui_reason_required')
    review = json.loads(bound_document(root, receipt.get('independent_review')))
    # Bind ALL receipt claims, including passport/proof hashes, scope and expiry;
    # exclude only the review reference itself to avoid a circular hash.
    subject = digest(json.dumps({k: v for k, v in receipt.items() if k != 'independent_review'}, sort_keys=True, separators=(',', ':')).encode())
    expected_review = 'release' if record.get('phase') == 'publish' else 'pre-creation'
    if not isinstance(receipt.get('implementer'), str) or not receipt['implementer'].strip() or not review.get('review_id') or review.get('phase') != expected_review or review.get('decision') != 'approved' or review.get('reviewer') == receipt.get('implementer') or not review.get('reviewer') or review.get('subject_sha256') != subject or (record.get('phase') == 'publish' and review.get('expires_at') != receipt.get('expires_at')):
        raise Refused('catalogue_independent_review_required')
    return {'checked': True, 'publisher': entry, 'scope': 'publication' if record.get('phase') == 'publish' else 'creation-only', 'source_files': len(actual), 'receipt_sha256': record['receipt']['sha256']}


def check(root, entry, registry, artifact_root=None):
    record = registry.get('publishers', {}).get(entry)
    if registry.get('version') != VERSION or not isinstance(record, dict):
        raise Refused('catalogue_publisher_unmapped')
    if record.get('status') == 'retired':
        raise Refused('catalogue_historical_publisher_retired')
    if record.get('status') == 'exempt':
        review = record.get('controller_review', {})
        if not isinstance(review, dict) or not record.get('reason') or review.get('decision') != 'approved' or not review.get('reviewer') or not review.get('review_id') or review.get('source_sha256') != record.get('sha256'):
            raise Refused('catalogue_no_ui_scope_unreviewed')
        subject = digest(json.dumps({k: v for k, v in record.items() if k != 'controller_review'}, sort_keys=True, separators=(',', ':')).encode())
        if review.get('classification_sha256') != subject:
            raise Refused('catalogue_no_ui_classification_changed')
        if record.get('requires_guarded_owner'):
            owners = record.get('guarded_by', [])
            if not owners or not all((registry['publishers'].get(owner, {}).get('status') in ['guarded', 'no-ui'] and any(entry == scope or entry.startswith(scope.rstrip('/') + '/') for scope in registry['publishers'][owner].get('source_scopes', []))) for owner in owners):
                raise Refused('catalogue_runtime_owner_scope_required')
        if digest(safe_file(root, entry).read_bytes()) != record.get('sha256'):
            raise Refused('catalogue_no_ui_source_changed')
        return {'checked': True, 'publisher': entry, 'scope': 'exempt-non-publication'}
    if record.get('status') not in ['guarded', 'no-ui']:
        raise Refused('catalogue_publisher_unmapped')
    return verify_receipt(root, entry, record, artifact_root, ui=record['status'] != 'no-ui')


def entrypoint(entry, root):
    """Single call used before a supported script's original executable body."""
    root = Path(root).resolve(strict=True)
    try:
        relative = Path(entry).resolve(strict=True).relative_to(root).as_posix()
        registry = json.loads(safe_file(root, '.catalogue-publication.json').read_text())
        return check(root, relative, registry, os.environ.get('VG_CATALOGUE_ARTIFACT_ROOT'))
    except (Refused, OSError, ValueError, KeyError, TypeError):
        # No request to disable this check or fallback execution is supported.
        raise SystemExit('CATALOGUE: publication refused; current registered catalogue evidence is required')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--registry', required=True)
    parser.add_argument('--entry', required=True)
    parser.add_argument('--artifact-root')
    args = parser.parse_args()
    root = Path(args.root).resolve(strict=True)
    registry = json.loads(safe_file(root, args.registry).read_text())
    print(json.dumps(check(root, args.entry, registry, args.artifact_root or os.environ.get('VG_CATALOGUE_ARTIFACT_ROOT')), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'checked': False, 'error': str(error) if isinstance(error, Refused) else 'catalogue_evidence_invalid'}), file=sys.stderr)
        sys.exit(78)
