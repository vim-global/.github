import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('guard.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write('ui/index.html', 'accepted template')
        self.write('artifact/index.html', 'compiled accepted template')
        self.write('publisher.py', 'print("should never run before gate")')
        self.write('passport.md', 'existing approved component passport')
        self.write('journal.md', 'Synthetic pre-implementation entry: reuse existing component, no owner data.')
        self.write('phone.json', json.dumps({'viewport': {'width': 393, 'height': 852}, 'overflow': False, 'states_checked': ['idle', 'error']}))
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'accepted source'], check=True)
        commit = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], text=True).strip()
        source = g.inventory(self.root, ['ui', 'publisher.py'])
        artifact = g.inventory(self.root / 'artifact', ['index.html'])
        issued = time.time()
        self.receipt = {'version': 1, 'phase': 'publish', 'status': 'catalogue-compared-before-implementation', 'publisher': 'publisher.py', 'implementer': 'Executor', 'source_commit': commit, 'source_scopes': ['ui', 'publisher.py'], 'source_files': source, 'artifact_scopes': ['index.html'], 'artifact_files': artifact, 'passport': {'component': 'EXISTING-001', 'version': '1', 'document': self.binding('passport.md')}, 'journal': self.binding('journal.md'), 'phone_proof': self.binding('phone.json'), 'issued_at': issued, 'expires_at': issued + 600}
        subject = g.digest(json.dumps(self.receipt, sort_keys=True, separators=(',', ':')).encode())
        self.write('review.json', json.dumps({'review_id': 'independent-fixture-review', 'phase': 'release', 'reviewer': 'Controller', 'decision': 'approved', 'subject_sha256': subject, 'expires_at': issued + 600}))
        self.receipt['independent_review'] = self.binding('review.json')
        self.record = {'status': 'guarded', 'phase': 'publish', 'source_scopes': ['ui', 'publisher.py'], 'artifact_scopes': ['index.html']}
        self.refresh_receipt()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def binding(self, name):
        return {'path': name, 'sha256': g.digest((self.root / name).read_bytes())}

    def refresh_receipt(self):
        self.write('receipt.json', json.dumps(self.receipt))
        self.record['receipt'] = self.binding('receipt.json')
        self.registry = {'version': 1, 'publishers': {'publisher.py': self.record}}

    def check(self):
        return g.check(self.root, 'publisher.py', self.registry, self.root / 'artifact')

    def test_exact_current_source_artifact_and_independent_proof(self):
        self.assertTrue(self.check()['checked'])

    def test_cli_publish_uses_explicit_artifact_environment(self):
        self.write('registry.json', json.dumps(self.registry))
        env = dict(os.environ, VG_CATALOGUE_ARTIFACT_ROOT=str(self.root / 'artifact'))
        result = subprocess.run(['python3', '-B', str(Path(__file__).with_name('guard.py')), '--root', str(self.root), '--registry', 'registry.json', '--entry', 'publisher.py'], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_catalogue_checked_candidate_can_be_built_before_final_phone_proof(self):
        self.record['phase'] = 'build'
        self.receipt['phase'] = 'build'
        for key in ['phone_proof', 'artifact_files', 'artifact_scopes', 'issued_at', 'expires_at', 'independent_review']:
            self.receipt.pop(key, None)
        self.write('journal.md', 'Synthetic scope: reuse accepted component before code; candidate is not a release.')
        self.receipt['journal'] = self.binding('journal.md')
        subject = g.digest(json.dumps(self.receipt, sort_keys=True, separators=(',', ':')).encode())
        self.write('review.json', json.dumps({'review_id': 'pre-creation-fixture', 'phase': 'pre-creation', 'reviewer': 'Controller', 'decision': 'approved', 'subject_sha256': subject}))
        self.receipt['independent_review'] = self.binding('review.json')
        self.refresh_receipt()
        self.assertEqual(self.check()['scope'], 'creation-only')
        self.record['phase'] = 'publish'
        with self.assertRaisesRegex(g.Refused, 'build_is_not_publication_approval'):
            self.check()

    def test_unknown_publisher(self):
        with self.assertRaisesRegex(g.Refused, 'publisher_unmapped'):
            g.check(self.root, 'new.py', self.registry)

    def test_retired_cannot_be_revived_by_receipt(self):
        self.record['status'] = 'retired'
        with self.assertRaisesRegex(g.Refused, 'retired'):
            self.check()

    def test_missing_receipt(self):
        (self.root / 'receipt.json').unlink()
        with self.assertRaisesRegex(g.Refused, 'file_missing'):
            self.check()

    def test_stale_receipt(self):
        self.write('receipt.json', '{}')
        with self.assertRaisesRegex(g.Refused, 'document_changed'):
            self.check()

    def test_ui_byte_change(self):
        self.write('ui/index.html', 'unreviewed')
        with self.assertRaisesRegex(g.Refused, 'source_changed'):
            self.check()

    def test_new_ui_file_not_omitted(self):
        self.write('ui/unreviewed.js', 'new')
        with self.assertRaisesRegex(g.Refused, 'source_changed'):
            self.check()

    def test_artifact_change(self):
        self.write('artifact/index.html', 'wrong compiled bytes')
        with self.assertRaisesRegex(g.Refused, 'artifact_changed'):
            self.check()

    def test_expired_admission(self):
        self.receipt['issued_at'] = time.time() - 1200
        self.receipt['expires_at'] = time.time() - 600
        self.refresh_receipt()
        with self.assertRaisesRegex(g.Refused, 'fresh_release_admission_required'):
            self.check()

    def test_indefinite_admission(self):
        self.receipt['expires_at'] = time.time() + 86400
        self.refresh_receipt()
        with self.assertRaisesRegex(g.Refused, 'fresh_release_admission_required'):
            self.check()

    def test_no_artifact_at_publish(self):
        with self.assertRaisesRegex(g.Refused, 'artifact_required'):
            g.check(self.root, 'publisher.py', self.registry)

    def test_missing_or_modified_phone_proof(self):
        self.write('phone.json', '{}')
        with self.assertRaisesRegex(g.Refused, 'document_changed'):
            self.check()

    def test_rebinding_phone_proof_requires_new_independent_review(self):
        self.write('phone.json', json.dumps({'viewport': {'width': 393, 'height': 852}, 'overflow': False, 'states_checked': ['replacement']}))
        self.receipt['phone_proof'] = self.binding('phone.json')
        self.refresh_receipt()
        with self.assertRaisesRegex(g.Refused, 'independent_review_required'):
            self.check()

    def test_missing_or_blank_implementer_cannot_be_independently_approved(self):
        for value in [None, '', '   ']:
            self.receipt['implementer'] = value
            self.receipt.pop('independent_review', None)
            subject = g.digest(json.dumps(self.receipt, sort_keys=True, separators=(',', ':')).encode())
            review = json.loads((self.root/'review.json').read_text())
            review['subject_sha256'] = subject
            self.write('review.json', json.dumps(review))
            self.receipt['independent_review'] = self.binding('review.json')
            self.refresh_receipt()
            with self.assertRaisesRegex(g.Refused, 'independent_review_required'):
                self.check()

    def test_self_review_rejected(self):
        review = json.loads((self.root / 'review.json').read_text())
        review['reviewer'] = 'Executor'
        self.write('review.json', json.dumps(review))
        self.receipt['independent_review'] = self.binding('review.json')
        self.refresh_receipt()
        with self.assertRaisesRegex(g.Refused, 'independent_review_required'):
            self.check()

    def test_source_commit_label_cannot_be_forged(self):
        self.receipt['source_commit'] = '0' * 40
        self.refresh_receipt()
        with self.assertRaisesRegex(g.Refused, 'commit_mismatch'):
            self.check()

    def test_symlink_escape(self):
        (self.root / 'ui/escape').symlink_to(self.root / 'artifact')
        with self.assertRaisesRegex(g.Refused, 'symlink_forbidden'):
            self.check()

    def test_no_ui_exemption_bound_to_exact_reviewed_script(self):
        sha = g.digest((self.root / 'publisher.py').read_bytes())
        self.registry['publishers']['publisher.py'] = {'status': 'exempt', 'reason': 'Synthetic non-publication maintenance fixture', 'controller_review': {'decision': 'approved', 'review_id': 'fixture-review', 'reviewer': 'Independent fixture controller', 'source_sha256': sha}, 'sha256': sha}
        self.assertEqual(self.check()['scope'], 'exempt-non-publication')
        self.write('publisher.py', 'changed into page publisher')
        with self.assertRaisesRegex(g.Refused, 'no_ui_source_changed'):
            self.check()


if __name__ == '__main__':
    unittest.main()
