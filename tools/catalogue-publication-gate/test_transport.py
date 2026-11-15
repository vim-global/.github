import importlib.util
import hashlib
import io
import json
import os
from unittest.mock import patch
import test_guard
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('transport', Path(__file__).with_name('transport.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def test_small_exact_read_commands_remain_available(self):
        for command in ['cat public_html/index.php', 'sha256sum public_html/style.css', 'stat public_html', 'ls -l public_html', 'pwd']:
            self.assertTrue(transport.read_only_shell(command), command)

    def test_shell_mutations_and_eval_are_not_read_exemptions(self):
        for command in ['cat x; cp bad public_html/index.php', 'cat x > public_html/index.php', 'cat $(touch mutation)', 'cat x && echo ok', 'php -r "file_put_contents(1,2);"', 'find . -exec rm {} +', 'bash -c echo', 'cat `id`', 'cat x\nrm x', 'cat /etc/passwd', 'cat public_html/../secret', 'cat public_html/wp-config.php', 'cat public_html/.env']:
            self.assertFalse(transport.read_only_shell(command), command)

    def test_read_only_command_does_not_require_or_create_a_release(self):
        with tempfile.TemporaryDirectory() as name:
            with transport.transport('cat public_html/index.php', 'missing-caller', name) as stream:
                self.assertIsNone(stream.stdin)
                self.assertEqual(stream.command, 'cat public_html/index.php')

    def synthetic_release(self, command, payload):
        fixture = test_guard.GateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.receipt['transport'] = [{'command_sha256': hashlib.sha256(command.encode()).hexdigest(), 'stdin_sha256': hashlib.sha256(payload).hexdigest()}]
        fixture.receipt.pop('independent_review')
        subject = test_guard.g.digest(json.dumps(fixture.receipt, sort_keys=True, separators=(',', ':')).encode())
        review = json.loads((fixture.root/'review.json').read_text())
        review['subject_sha256'] = subject
        fixture.write('review.json', json.dumps(review))
        fixture.receipt['independent_review'] = fixture.binding('review.json')
        fixture.refresh_receipt()
        fixture.write('.catalogue-publication.json', json.dumps(fixture.registry))
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, VG_CATALOGUE_ARTIFACT_ROOT=str(fixture.root/'artifact')).start()
        # Read-only import locates its own guard module; no network is opened.
        return fixture

    def test_exact_reviewed_payload_is_frozen_before_connection_body(self):
        command, payload = 'tar -xf - -C public_html', b'exact reviewed synthetic package'
        fixture = self.synthetic_release(command, payload)
        mutable = io.BytesIO(payload)
        with transport.transport(command, fixture.root/'publisher.py', fixture.root, stdin=mutable) as frozen:
            mutable.seek(0)
            mutable.write(b'UNREVIEWED CHANGED BYTES')
            self.assertEqual(frozen.stdin.read(), payload)
            self.assertEqual(frozen.command, command)
        self.assertTrue(frozen.stdin.closed)

    def test_changed_payload_and_command_refuse_before_body(self):
        command, payload = 'tar -xf - -C public_html', b'exact synthetic package'
        fixture = self.synthetic_release(command, payload)
        for cmd, data in [(command, b'changed'), (command+'-other', payload)]:
            with self.assertRaises(SystemExit):
                with transport.transport(cmd, fixture.root/'publisher.py', fixture.root, input_data=data):
                    self.fail('connection body reached')

    def test_consumer_executes_exact_issued_command_and_frozen_stream(self):
        command, payload = 'tar -xf - -C public_html', b'exact synthetic package'
        fixture = self.synthetic_release(command, payload)
        observed = []
        def fake_run(argv, **kwargs):
            observed.append((argv, kwargs['stdin'].read()))
            return 'synthetic result'
        # Guard's git reconstruction remains real; replace only after import
        # would also replace its subprocess module. Delegate git to the real one.
        actual_run = transport.subprocess.run
        def selective_run(argv, **kwargs):
            return fake_run(argv, **kwargs) if argv[0] == 'synthetic-ssh' else actual_run(argv, **kwargs)
        with patch.object(transport.subprocess, 'run', selective_run):
            result = transport.run_checked(['synthetic-ssh', 'reviewed-host'], command, fixture.root/'publisher.py', fixture.root, input=payload)
        self.assertEqual(result, 'synthetic result')
        self.assertEqual(observed, [(['synthetic-ssh', 'reviewed-host', command], payload)])

    def test_changed_source_after_capture_refuses_before_body(self):
        command, payload = 'tar -xf - -C public_html', b'exact synthetic package'
        fixture = self.synthetic_release(command, payload)
        class Drift(io.BytesIO):
            def read(inner, count):
                fixture.write('ui/index.html', 'changed after initial admission')
                return super().read(count)
        with self.assertRaises(SystemExit):
            with transport.transport(command, fixture.root/'publisher.py', fixture.root, stdin=Drift(payload)):
                self.fail('connection body reached')

    def test_unknown_mutator_cannot_reach_connection_body(self):
        reached = False
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(SystemExit):
                with transport.transport('cp staged public_html/index.php', 'missing-caller', name):
                    reached = True
        self.assertFalse(reached)


if __name__ == '__main__':
    unittest.main()
