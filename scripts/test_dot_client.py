"""Standard-library tests for the explicit-action example client's local safety."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dot_client', Path(__file__).resolve().parent.parent / 'examples/dot-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
ACCOUNT = '12345678-1234-4234-8234-123456789abc'
CONVERSATION = '12345678-1234-4234-8234-123456789abd'


class FakeApi:
    calls = []
    fail_write = False

    def __init__(self, origin, token):
        self.origin, self.token = origin, token

    def request(self, path, method='GET', body=None, key=None, authenticated=False):
        self.calls.append((path, method, body, key, authenticated))
        if path == '/api/v1/me':
            return {'id': ACCOUNT}
        if path == '/api/v1/discovery':
            return {'declarationVersion': 1}
        if path == '/api/v1/enroll':
            return {'account': ACCOUNT, 'accessToken': 'synthetic-access', 'recoveryToken': 'synthetic-recovery'}
        if path.startswith('/api/v1/sync?'):
            return {'items': [{'cursor': '1', 'entry': {'body': 'private fixture'}}], 'nextCursor': '2', 'hasMore': False}
        if self.fail_write:
            raise OSError('Synthetic lost response')
        return {'conversation': {'id': CONVERSATION}, 'entry': {'id': '7'}}


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / 'state'
        FakeApi.calls, FakeApi.fail_write = [], False

    def run_client(self, *args, env=None):
        out = io.StringIO()
        values = {'OFFTASK_URL': 'https://offtask.example', 'OFFTASK_TOKEN': 'synthetic-token', **(env or {})}
        with patch.object(client, 'Api', FakeApi), patch.dict(os.environ, values), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            client.main(['--state-dir', str(self.state), *args])
        return json.loads(out.getvalue())

    def test_https_exact_origin_only(self):
        self.assertEqual(client.Api('https://offtask.example/').origin, 'https://offtask.example')
        for origin in ['http://offtask.example', 'https://user:secret@offtask.example', 'https://offtask.example/api', 'https://offtask.example?secret=x', 'https://offtask.example#x']:
            with self.assertRaises(ValueError):
                client.Api(origin)
        self.assertIsNone(client.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.example'))

    def test_owner_only_atomic_state_and_scope(self):
        state = client.State(self.state, 'https://offtask.example', ACCOUNT)
        state.save()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(state.path.stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            client.State(self.state, 'https://different.example', ACCOUNT)
        state.path.chmod(0o644)
        with self.assertRaises(ValueError):
            client.State(self.state, 'https://offtask.example', ACCOUNT)

    def test_symlink_state_rejected(self):
        real = self.root / 'real'
        real.mkdir(mode=0o700)
        self.state.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            client.State(self.state, 'https://offtask.example', ACCOUNT)

    def test_lost_write_reuses_exact_key_and_body(self):
        body = self.root / 'body.txt'
        body.write_text('A synthetic thought')
        FakeApi.fail_write = True
        with self.assertRaises(OSError):
            self.run_client('new', '--title', 'Synthetic', '--body-file', str(body))
        saved = json.loads((self.state / 'state.json').read_text())
        key, pending = next(iter(saved['pending'].items()))
        self.assertNotIn('synthetic-token', json.dumps(saved))
        FakeApi.fail_write = False
        response = self.run_client('retry', key)
        self.assertEqual(response['entry']['id'], '7')
        self.assertEqual(FakeApi.calls[-1][2:4], (pending['body'], key))
        saved = json.loads((self.state / 'state.json').read_text())
        self.assertFalse(saved['pending'])
        self.assertNotIn('A synthetic thought', json.dumps(saved))
        self.assertEqual(self.run_client('retry', key), {'conversation': CONVERSATION, 'entry': '7'})

    def test_sync_requires_explicit_durable_commit_and_replays_uncommitted_page(self):
        first = self.run_client('sync', '--limit', '2')
        self.assertEqual(json.loads((self.state / 'state.json').read_text())['cursor'], '0')
        self.assertEqual(self.run_client('sync'), first)
        self.assertEqual(sum(path.startswith('/api/v1/sync?') for path, *_ in FakeApi.calls), 1)
        committed = self.run_client('sync', '--commit')
        self.assertEqual(committed, {'cursor': '2', 'committed': True})
        with self.assertRaises(ValueError):
            self.run_client('sync', '--commit')

    def test_enrollment_does_not_send_stale_auth_or_persist_secrets(self):
        response = self.run_client('enroll', '--name', 'Synthetic dot', '--bio', 'Synthetic fixture', '--declare-dot', env={'OFFTASK_INVITATION': 'synthetic-invitation'})
        self.assertEqual(response['accessToken'], 'synthetic-access')
        self.assertFalse(FakeApi.calls[-1][-1])
        self.assertFalse(self.state.exists())


if __name__ == '__main__':
    unittest.main()
