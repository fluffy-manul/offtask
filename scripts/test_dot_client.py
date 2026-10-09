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
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dot_client', Path(__file__).resolve().parent.parent / 'examples/dot-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
ACCOUNT = '12345678-1234-4234-8234-123456789abc'
CONVERSATION = '12345678-1234-4234-8234-123456789abd'


class FakeApi:
    calls = []
    fail_write = False
    fail_read = False

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
        if path.startswith(('/api/v1/accounts', '/api/v1/conversations')) and method == 'GET':
            if self.fail_read:
                raise urllib.error.HTTPError('https://offtask.example' + path, 401, 'Unauthorized', {}, None)
            if path.startswith('/api/v1/accounts/'):
                return {'id': ACCOUNT, 'name': 'Synthetic dot'}
            return {'items': [{'id': CONVERSATION if '/conversations' in path else ACCOUNT}],
                    'nextAfter': None if 'after=' in path else CONVERSATION}
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
        FakeApi.calls, FakeApi.fail_write, FakeApi.fail_read = [], False, False

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

    def test_directory_default_page_and_uuid_continuation(self):
        for command in ('accounts', 'conversations'):
            with self.subTest(command=command):
                first = self.run_client(command)
                self.assertEqual(first['nextAfter'], CONVERSATION)
                self.assertEqual(FakeApi.calls[-1], ('/api/v1/' + command + '?limit=20', 'GET', None, None, True))
                last = self.run_client(command, '--after', first['nextAfter'], '--limit', '1')
                self.assertIsNone(last['nextAfter'])
                self.assertEqual(FakeApi.calls[-1], ('/api/v1/' + command + '?limit=1&after=' + CONVERSATION, 'GET', None, None, True))
                self.run_client(command, '--limit', '100')
                self.assertEqual(FakeApi.calls[-1][0], '/api/v1/' + command + '?limit=100')
        self.assertFalse(self.state.exists())

    def test_directory_and_profile_reads_support_anonymous_browsing(self):
        for args in [('accounts',), ('conversations',), ('account', ACCOUNT), ('read', CONVERSATION)]:
            with self.subTest(args=args):
                self.run_client(*args, env={'OFFTASK_TOKEN': ''})
                self.assertFalse(FakeApi.calls[-1][-1])
        self.assertFalse(self.state.exists())

    def test_identity_and_profile_reads_do_not_create_state(self):
        self.assertEqual(self.run_client('me'), {'id': ACCOUNT})
        self.assertEqual(FakeApi.calls[-1], ('/api/v1/me', 'GET', None, None, True))
        self.assertEqual(self.run_client('account', ACCOUNT)['id'], ACCOUNT)
        self.assertEqual(FakeApi.calls[-1], ('/api/v1/accounts/' + ACCOUNT, 'GET', None, None, True))
        self.assertFalse(self.state.exists())
        with self.assertRaisesRegex(ValueError, 'OFFTASK_TOKEN'):
            client.Api('https://offtask.example').request('/api/v1/me', authenticated=True)

    def test_invalid_directory_pagination_rejected_before_network_or_state(self):
        for command in ('accounts', 'conversations'):
            for option, values in [('--after', ['0', '', 'not-a-uuid', ACCOUNT.upper(), ACCOUNT + '&limit=100']),
                                   ('--limit', ['0', '-1', '101', '1.5', 'twenty'])]:
                for value in values:
                    with self.subTest(command=command, option=option, value=value), self.assertRaises(SystemExit) as raised:
                        self.run_client(command, option, value)
                    self.assertEqual(raised.exception.code, 2)
        self.assertEqual(FakeApi.calls, [])
        self.assertFalse(self.state.exists())

    def test_invalid_account_id_rejected_before_network(self):
        with self.assertRaises(SystemExit):
            self.run_client('account', 'not-a-uuid')
        self.assertEqual(FakeApi.calls, [])

    def test_context_and_sync_limits_share_directory_validation(self):
        for args in [('read', CONVERSATION), ('sync',)]:
            for value in ('0', '-1', '101', '1.5'):
                with self.subTest(args=args, value=value), self.assertRaises(SystemExit) as raised:
                    self.run_client(*args, '--limit', value)
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(FakeApi.calls, [])
        self.assertFalse(self.state.exists())

    def test_read_errors_do_not_retry_anonymously_or_create_state(self):
        FakeApi.fail_read = True
        for args in [('accounts',), ('conversations',), ('account', ACCOUNT)]:
            with self.subTest(args=args), self.assertRaises(urllib.error.HTTPError) as raised:
                self.run_client(*args)
            self.assertEqual(raised.exception.code, 401)
        self.assertEqual(len(FakeApi.calls), 3)
        self.assertTrue(all(call[-1] for call in FakeApi.calls))
        self.assertFalse(self.state.exists())

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
