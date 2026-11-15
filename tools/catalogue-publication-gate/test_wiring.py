import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parent
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
wire = module('wire')
coverage = module('coverage')


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        target = self.root / 'tools/catalogue-publication-gate'
        target.mkdir(parents=True)
        for name in ['guard.py', 'preflight.mjs', 'preflight.cjs', 'wire.py']:
            shutil.copyfile(ROOT / name, target / name)
        (self.root / '.catalogue-publication.json').write_text(json.dumps({'version': 1, 'publishers': {'release.py': {'status': 'retired'}, 'release.mjs': {'status': 'retired'}}}))

    def run_entry(self, entry, command):
        result = subprocess.run(command + [str(self.root / entry)], cwd=self.root, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'side-effect').exists(), result.stderr)

    def test_python_refuses_before_import_side_effect(self):
        (self.root / 'bad_import.py').write_text("from pathlib import Path\nPath('side-effect').write_text('network or deploy body ran')\n")
        (self.root / 'release.py').write_text('"""Existing docstring."""\nfrom __future__ import annotations\nimport bad_import\n')
        wire.wire(self.root, 'release.py')
        self.run_entry('release.py', ['python3', '-B'])

    def test_approved_shell_guard_preserves_binary_stdout(self):
        name = 'release.sh'
        p = self.root/name
        p.write_text('#!/bin/sh\nprintf "payload"\n')
        wire.wire(self.root, name)
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        (self.root/'.catalogue-publication.json').write_text(json.dumps({'version':1,'publishers':{name:{'status':'exempt','reason':'synthetic output contract','sha256':digest,'controller_review':{'decision':'approved','review_id':'synthetic-independent','reviewer':'Controller','source_sha256':digest}}}}))
        result = subprocess.run(['sh', str(p)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'payload')

    def test_missing_shared_guard_refuses_before_body(self):
        (self.root / 'release.py').write_text("from pathlib import Path\nPath('side-effect').write_text('ran')\n")
        wire.wire(self.root, 'release.py')
        (self.root / 'tools/catalogue-publication-gate/guard.py').unlink()
        self.run_entry('release.py', ['python3', '-B'])

    def test_missing_registry_refuses_before_body(self):
        (self.root / 'release.py').write_text("from pathlib import Path\nPath('side-effect').write_text('ran')\n")
        wire.wire(self.root, 'release.py')
        (self.root / '.catalogue-publication.json').unlink()
        self.run_entry('release.py', ['python3', '-B'])

    def test_node_refuses_before_other_static_imports(self):
        (self.root / 'bad-import.mjs').write_text("import {writeFileSync} from 'node:fs';writeFileSync('side-effect','ran');\n")
        (self.root / 'release.mjs').write_text("import './bad-import.mjs';\n")
        wire.wire(self.root, 'release.mjs')
        self.run_entry('release.mjs', ['node'])

    def test_commonjs_refuses_before_other_imports(self):
        (self.root / 'release.cjs').write_text("require('node:fs').writeFileSync('side-effect','ran');\n")
        wire.wire(self.root, 'release.cjs')
        self.run_entry('release.cjs', ['node'])

    def test_node_library_import_is_preserved(self):
        (self.root / 'library.mjs').write_text('export const ready=true;\n')
        wire.wire(self.root, 'library.mjs')
        (self.root / 'consumer.mjs').write_text("import {ready} from './library.mjs';if(!ready)throw Error('library lost');console.log('library preserved');\n")
        result = subprocess.run(['node', str(self.root / 'consumer.mjs')], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_commonjs_library_import_is_preserved(self):
        (self.root / 'library.cjs').write_text('module.exports={ready:true};\n')
        wire.wire(self.root, 'library.cjs')
        (self.root / 'consumer.cjs').write_text("if(!require('./library.cjs').ready)throw Error('library lost');\n")
        result = subprocess.run(['node', str(self.root / 'consumer.cjs')], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_commonjs_hashbang_and_strict_mode_preserved(self):
        path = self.root / 'strict.cjs'
        path.write_text("#!/usr/bin/env node\n'use strict';\nif((function(){return this})()!==undefined)throw Error('strict lost');\n")
        wire.wire(self.root, 'strict.cjs')
        self.assertTrue(path.read_text().startswith('#!/usr/bin/env node\n\'use strict\';'))
        self.assertTrue(coverage.wired_first(self.root, 'strict.cjs', path.read_text()))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        registry = {'version': 1, 'publishers': {'strict.cjs': {'status': 'exempt', 'reason': 'Isolated non-publication strict-mode fixture', 'sha256': digest, 'controller_review': {'decision': 'approved', 'review_id': 'fixture', 'reviewer': 'Fixture controller', 'source_sha256': digest}}}}
        (self.root / '.catalogue-publication.json').write_text(json.dumps(registry))
        result = subprocess.run(['node', str(path)], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'', 'preflight must not pollute machine-readable/binary publisher output')

    def test_esm_hashbang_preserved_and_blocked(self):
        (self.root / 'release.mjs').write_text("#!/usr/bin/env node\nimport {writeFileSync} from 'node:fs';writeFileSync('side-effect','ran');\n")
        wire.wire(self.root, 'release.mjs')
        self.assertTrue((self.root / 'release.mjs').read_text().startswith('#!/usr/bin/env node\n'))
        self.run_entry('release.mjs', ['node'])

    def test_shell_refuses_before_body(self):
        (self.root / 'release.sh').write_text('#!/bin/sh\ntouch side-effect\n')
        wire.wire(self.root, 'release.sh')
        self.assertTrue(coverage.wired_first(self.root, 'release.sh', (self.root / 'release.sh').read_text()))
        self.run_entry('release.sh', ['sh'])

    def test_publisher_under_fixture_folder_not_silently_excluded(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'fixtures').mkdir()
        (self.root / 'fixtures/deploy.py').write_text('print("publisher")\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'fixtures/deploy.py'], check=True)
        self.assertIn('fixtures/deploy.py', coverage.candidates(self.root))

    def test_service_and_extensionless_entry_are_candidates(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'publish-worker.service').write_text('[Service]\nExecStart=/usr/local/bin/publish-page\n')
        (self.root / 'entry').write_text('#!/bin/sh\necho work\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'publish-worker.service', 'entry'], check=True)
        self.assertIn('publish-worker.service', coverage.candidates(self.root))
        self.assertIn('entry', coverage.candidates(self.root))

    def test_new_publisher_fails_coverage(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'new-deploy.py').write_text('print("new path")\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'new-deploy.py'], check=True)
        result = coverage.audit(self.root)
        self.assertFalse(result['checked'])
        self.assertIn('new-deploy.py:unmapped', result['failures'])

    def test_filename_independent_upload_detection(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'innocent.py').write_text('import ftplib\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'innocent.py'], check=True)
        self.assertIn('innocent.py', coverage.candidates(self.root))

    def test_plain_ssh_subprocess_is_detected(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'innocent.py').write_text('import subprocess\nsubprocess.run(["ssh","example.invalid","install reviewed-artifact target"])\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'innocent.py'], check=True)
        self.assertIn('innocent.py', coverage.candidates(self.root))

    def test_php_historical_publisher_is_unconditionally_retired_before_body(self):
        name = 'install.php'
        (self.root/name).write_text("<?php\nfile_put_contents('side-effect', 'never');\n")
        wire.wire(self.root, name)
        self.assertTrue(coverage.wired_first(self.root, name, (self.root/name).read_text()))
        self.assertFalse(coverage.wired_first(self.root, name, "<?php\n// VG-CATALOGUE-PUBLICATION-PREFLIGHT-1\nfile_put_contents('side-effect', 'unsafe');"))
        if shutil.which('php'):
            result = subprocess.run(['php', str(self.root/name)], cwd=self.root, capture_output=True)
            self.assertEqual(result.returncode, 78)
            self.assertFalse((self.root/'side-effect').exists())

    def test_explicit_exemption_is_hash_checked_even_when_scanner_no_longer_matches(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        p = self.root/'ordinary.txt'
        p.write_text('changed bytes')
        (self.root/'.catalogue-publication.json').write_text(json.dumps({'version':1,'publishers':{'ordinary.txt':{'status':'exempt','entry_kind':'library','reason':'synthetic classification','sha256':'a'*64,'controller_review':{'decision':'approved','review_id':'synthetic-peer','reviewer':'Controller','source_sha256':'a'*64}}}}))
        self.assertIn('ordinary.txt:no-ui-classification-stale', coverage.audit(self.root)['failures'])

    def test_marker_comment_does_not_count_as_wiring(self):
        self.assertFalse(coverage.wired_first(self.root, 'release.py', '# ' + coverage.MARKER + '\nprint("unsafe")\n'))

    def test_import_before_guard_does_not_count_as_wiring(self):
        self.assertFalse(coverage.wired_first(self.root, 'release.py', 'import bad_import\n' + wire.PYTHON))

    def test_exact_first_guard_is_detected(self):
        self.assertTrue(coverage.wired_first(self.root, 'release.py', '"""Docstring"""\nfrom __future__ import annotations\n' + wire.PYTHON + 'print("body")\n'))


if __name__ == '__main__':
    unittest.main()
