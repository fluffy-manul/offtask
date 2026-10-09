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
import urllib.request
from email.message import Message
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dot_client', Path(__file__).resolve().parent.parent / 'examples/dot-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
ACCOUNT = '12345678-1234-4234-8234-123456789abc'
CONVERSATION = '12345678-1234-4234-8234-123456789abd'
GENERATION = '12345678-1234-4234-8234-123456789abe'


class FakeApi:
    calls = []
    fail_write = False
    fail_read = False
    hints = [{'event': 'ready', 'data': {'subscription': 'inbox', 'pollSeconds': 1}},
             {'event': 'available', 'data': {'subscription': 'inbox'}}]

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
        if path.startswith('/api/v1/subscriptions'):
            if self.fail_read:
                raise urllib.error.HTTPError('https://offtask.example' + path, 401, 'Unauthorized', {}, None)
            if self.fail_write and method != 'GET':
                raise OSError('Synthetic lost response')
            if '/events?' in path:
                return {'subscription': {'name': 'inbox', 'generation': GENERATION},
                        'items': [{'cursor': '9007199254740993', 'entry': {'body': 'private fixture'}}],
                        'nextCursor': '9007199254740993', 'hasMore': False}
            if path.endswith('/ack'):
                return {'acknowledgedCursor': json.loads(body)['cursor']}
            return {'name': 'inbox', 'generation': GENERATION, 'senders': [ACCOUNT], 'visibility': 'private',
                    'acknowledgedCursor': '0', 'deliveredCursor': '0'}
        if path.startswith('/api/v1/sync?'):
            return {'items': [{'cursor': '1', 'entry': {'body': 'private fixture'}}], 'nextCursor': '2', 'hasMore': False}
        if self.fail_write:
            raise OSError('Synthetic lost response')
        return {'conversation': {'id': CONVERSATION}, 'entry': {'id': '7'}}

    def watch(self, name):
        self.calls.append(('/api/v1/subscriptions/' + name + '/stream', 'GET', None, None, True))
        if self.fail_read:
            raise OSError('Synthetic dropped stream')
        yield from self.hints


class FakeStream(io.BytesIO):
    def __init__(self, body=b'', content_type='text/event-stream; charset=utf-8'):
        super().__init__(body)
        self.headers = {'Content-Type': content_type}


class RecordingOpener:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return self.response


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
        if args[0] == 'watch':
            return [json.loads(line) for line in out.getvalue().splitlines()]
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

    def test_subscription_commands_are_authenticated_and_stateless(self):
        self.run_client('subscribe', 'inbox', '--sender', ACCOUNT)
        call = FakeApi.calls[-1]
        self.assertEqual(call[:2], ('/api/v1/subscriptions/inbox', 'PUT'))
        self.assertEqual(json.loads(call[2]), {'senders': [ACCOUNT], 'visibility': 'private'})
        self.assertEqual(call[3:], (None, True))
        self.run_client('subscribe', 'inbox', '--sender', ACCOUNT, '--sender', CONVERSATION, '--visibility', 'all')
        self.assertEqual(json.loads(FakeApi.calls[-1][2]), {'senders': [ACCOUNT, CONVERSATION], 'visibility': 'all'})
        for args, path in [(('subscriptions',), '/api/v1/subscriptions'),
                           (('subscription', 'inbox'), '/api/v1/subscriptions/inbox'),
                           (('inbox', 'inbox'), '/api/v1/subscriptions/inbox/events?limit=100')]:
            self.run_client(*args)
            self.assertEqual(FakeApi.calls[-1], (path, 'GET', None, None, True))
        self.run_client('unsubscribe', 'inbox', '--generation', GENERATION)
        self.assertEqual(FakeApi.calls[-1], ('/api/v1/subscriptions/inbox', 'DELETE', json.dumps({'generation': GENERATION}), None, True))
        self.assertFalse(self.state.exists())
        self.assertFalse(any(call[0] == '/api/v1/me' for call in FakeApi.calls))

    def test_subscription_and_sender_bounds_fail_before_network(self):
        for command in ('subscribe', 'subscription', 'inbox', 'ack', 'unsubscribe', 'watch'):
            suffix = ['--sender', ACCOUNT] if command == 'subscribe' else ['--cursor', '0', '--generation', GENERATION] if command == 'ack' else ['--generation', GENERATION] if command == 'unsubscribe' else []
            for name in ('', 'A', 'x' * 65, '../escape', 'a/b', 'naïve', 'a?b', 'a\nb', 'a%2fb', 'a b'):
                with self.subTest(command=command, name=name), self.assertRaises(SystemExit) as raised:
                    self.run_client(command, name, *suffix)
                self.assertEqual(raised.exception.code, 2)
        for senders in ([], ['--sender', ACCOUNT] * 33, ['--sender', ACCOUNT.upper()], ['--sender', 'not-a-uuid']):
            with self.subTest(senders=senders), self.assertRaises(SystemExit):
                self.run_client('subscribe', 'inbox', *senders)
        with self.assertRaises(SystemExit):
            self.run_client('subscribe', 'inbox', '--sender', ACCOUNT, '--visibility', 'friends')
        self.assertEqual(FakeApi.calls, [])
        self.assertFalse(self.state.exists())
        for name in ('a', 'a' * 64, '0_-'):
            self.run_client('subscription', name)
            self.assertEqual(FakeApi.calls[-1][0], '/api/v1/subscriptions/' + name)
        self.run_client('subscribe', 'inbox', *(['--sender', ACCOUNT] * 32))
        self.assertEqual(len(json.loads(FakeApi.calls[-1][2])['senders']), 32)

    def test_inbox_never_acknowledges_and_can_repeat_without_disk(self):
        first = self.run_client('inbox', 'inbox')
        self.assertEqual(self.run_client('inbox', 'inbox'), first)
        self.assertTrue(all(call[1] == 'GET' for call in FakeApi.calls))
        self.assertEqual(len(FakeApi.calls), 2)
        self.assertFalse(self.state.exists())
        for value in ('0', '-1', '101', '1.5', 'infinity'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.run_client('inbox', 'inbox', '--limit', value)
        self.assertEqual(len(FakeApi.calls), 2)
        self.run_client('inbox', 'inbox', '--limit', '1')
        self.assertEqual(FakeApi.calls[-1][0], '/api/v1/subscriptions/inbox/events?limit=1')

    def test_ack_requires_exact_decimal_string_and_is_explicit(self):
        for value in ('0', '0001', '9007199254740993', '9223372036854775807'):
            self.assertEqual(self.run_client('ack', 'inbox', '--cursor', value, '--generation', GENERATION), {'acknowledgedCursor': value})
            self.assertEqual(FakeApi.calls[-1], ('/api/v1/subscriptions/inbox/ack', 'POST', json.dumps({'cursor': value, 'generation': GENERATION}), None, True))
        count = len(FakeApi.calls)
        for value in ('', '-1', '+1', '1.0', '1e3', '1/ack', 'NaN', ' 1', '1 ', '１', '١', '9223372036854775808', '1' * 100):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.run_client('ack', 'inbox', '--cursor', value, '--generation', GENERATION)
        with self.assertRaises(SystemExit):
            self.run_client('ack', 'inbox')
        self.assertEqual(len(FakeApi.calls), count)
        self.assertFalse(self.state.exists())

    def test_ack_requires_exact_subscription_generation_before_network(self):
        with self.assertRaises(SystemExit):
            self.run_client('ack', 'inbox', '--cursor', '1')
        for generation in ('', 'not-a-uuid', GENERATION.upper(), GENERATION + '/ack'):
            with self.subTest(generation=generation), self.assertRaises(SystemExit):
                self.run_client('ack', 'inbox', '--cursor', '1', '--generation', generation)
        self.assertEqual(FakeApi.calls, [])
        page = self.run_client('inbox', 'inbox')
        self.run_client('ack', 'inbox', '--cursor', page['nextCursor'], '--generation', page['subscription']['generation'])
        self.assertEqual(json.loads(FakeApi.calls[-1][2]), {'cursor': page['nextCursor'], 'generation': GENERATION})
        self.assertFalse(self.state.exists())

    def test_unsubscribe_requires_intended_generation_without_lookup(self):
        with self.assertRaises(SystemExit):
            self.run_client('unsubscribe', 'inbox')
        for generation in ('', 'not-a-uuid', GENERATION.upper(), GENERATION + '/ack'):
            with self.subTest(generation=generation), self.assertRaises(SystemExit):
                self.run_client('unsubscribe', 'inbox', '--generation', generation)
        self.assertEqual(FakeApi.calls, [])
        self.run_client('unsubscribe', 'inbox', '--generation', GENERATION)
        self.assertEqual(FakeApi.calls, [('/api/v1/subscriptions/inbox', 'DELETE', json.dumps({'generation': GENERATION}), None, True)])
        self.assertFalse(self.state.exists())

    def test_subscription_errors_are_not_retried(self):
        FakeApi.fail_read = True
        for args in [('subscriptions',), ('subscription', 'inbox'), ('inbox', 'inbox')]:
            with self.subTest(args=args), self.assertRaises(urllib.error.HTTPError):
                self.run_client(*args)
        self.assertEqual(len(FakeApi.calls), 3)
        FakeApi.fail_read, FakeApi.fail_write = False, True
        for args in [('subscribe', 'inbox', '--sender', ACCOUNT), ('ack', 'inbox', '--cursor', '1', '--generation', GENERATION), ('unsubscribe', 'inbox', '--generation', GENERATION)]:
            with self.subTest(args=args), self.assertRaises(OSError):
                self.run_client(*args)
        self.assertEqual(len(FakeApi.calls), 6)
        self.assertTrue(all(call[-1] for call in FakeApi.calls))
        self.assertFalse(self.state.exists())

    def test_subscription_conflict_and_ack_overrun_are_explicit_single_failures(self):
        for args, status in [(('subscribe', 'inbox', '--sender', ACCOUNT), 409),
                             (('ack', 'inbox', '--cursor', '100', '--generation', GENERATION), 400),
                             (('ack', 'inbox', '--cursor', '1', '--generation', GENERATION), 409),
                             (('unsubscribe', 'inbox', '--generation', GENERATION), 409)]:
            error = urllib.error.HTTPError('https://offtask.example/api/v1/subscriptions/inbox', status, 'Synthetic rejection', {}, None)
            with patch.object(FakeApi, 'request', side_effect=error) as requested:
                with self.subTest(args=args), self.assertRaises(urllib.error.HTTPError) as raised:
                    self.run_client(*args)
                self.assertEqual(raised.exception.code, status)
                self.assertEqual(requested.call_count, 1)
                self.assertTrue(requested.call_args.kwargs['authenticated'])
        self.assertFalse(self.state.exists())

    def test_subscribe_repetition_is_only_at_callers_request(self):
        args = ('subscribe', 'inbox', '--sender', ACCOUNT, '--visibility', 'public')
        self.run_client(*args)
        self.assertEqual(len(FakeApi.calls), 1)
        self.run_client(*args)
        self.assertEqual(len(FakeApi.calls), 2)
        self.assertEqual(FakeApi.calls[0], FakeApi.calls[1])
        self.assertFalse(self.state.exists())

    def test_watch_is_one_connection_with_no_ack_local_state_or_reconnect(self):
        self.assertEqual(self.run_client('watch', 'inbox'), FakeApi.hints)
        self.assertEqual(FakeApi.calls, [('/api/v1/subscriptions/inbox/stream', 'GET', None, None, True)])
        self.assertFalse(self.state.exists())
        FakeApi.fail_read = True
        with self.assertRaisesRegex(OSError, 'dropped stream'):
            self.run_client('watch', 'inbox')
        self.assertEqual(len(FakeApi.calls), 2)
        self.assertFalse(self.state.exists())

    def test_watch_flushes_each_hint(self):
        with patch.object(client, 'Api', FakeApi), patch.dict(os.environ, {'OFFTASK_URL': 'https://offtask.example', 'OFFTASK_TOKEN': 'synthetic-token'}), patch('builtins.print') as printed:
            client.main(['--state-dir', str(self.state), 'watch', 'inbox'])
        lines = [call for call in printed.call_args_list if call.kwargs.get('flush')]
        self.assertEqual(len(lines), 2)
        self.assertEqual([json.loads(call.args[0]) for call in lines], FakeApi.hints)
        self.assertTrue(all('\n' not in call.args[0] for call in lines))

    def test_actual_subscription_requests_require_token_before_opening(self):
        api = client.Api('https://offtask.example')
        with patch.object(api.opener, 'open') as opened:
            for path, method, body in [('/api/v1/subscriptions', 'GET', None),
                                       ('/api/v1/subscriptions/inbox', 'GET', None),
                                       ('/api/v1/subscriptions/inbox', 'PUT', '{}'),
                                       ('/api/v1/subscriptions/inbox/events?limit=100', 'GET', None),
                                       ('/api/v1/subscriptions/inbox/ack', 'POST', json.dumps({'cursor': '1', 'generation': GENERATION})),
                                       ('/api/v1/subscriptions/inbox', 'DELETE', json.dumps({'generation': GENERATION}))]:
                with self.assertRaisesRegex(ValueError, 'OFFTASK_TOKEN'):
                    api.request(path, method, body, authenticated=True)
            with self.assertRaisesRegex(ValueError, 'OFFTASK_TOKEN'):
                list(api.watch('inbox'))
            opened.assert_not_called()

    def test_actual_watch_headers_timeout_and_content_type(self):
        api = client.Api('https://offtask.example', 'synthetic-token')
        response = FakeStream(b'event: ready\ndata: {"subscription":"inbox","pollSeconds":1}\n\n')
        api.opener = RecordingOpener(response)
        self.assertEqual(list(api.watch('inbox')), [FakeApi.hints[0]])
        self.assertTrue(response.closed)
        request, timeout = api.opener.calls[0]
        self.assertEqual(request.full_url, 'https://offtask.example/api/v1/subscriptions/inbox/stream')
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertEqual(request.get_header('Accept'), 'text/event-stream')
        self.assertIsNone(request.get_header('Last-event-id'))
        self.assertEqual(timeout, 25)
        self.assertEqual(len(api.opener.calls), 1)
        for content_type in ('text/html', 'application/json', ''):
            response = FakeStream(b'not an event stream', content_type)
            api.opener = RecordingOpener(response)
            with self.assertRaisesRegex(ValueError, 'text/event-stream'):
                list(api.watch('inbox'))
            self.assertTrue(response.closed)
            self.assertEqual(len(api.opener.calls), 1)

    def test_authenticated_watch_and_requests_never_follow_redirects(self):
        class RedirectFixture(urllib.request.HTTPSHandler):
            def __init__(self, destination):
                super().__init__()
                self.destination, self.requests = destination, []

            def https_open(self, request):
                self.requests.append(request)
                headers = Message()
                headers['Location'] = self.destination
                response = urllib.request.addinfourl(io.BytesIO(b''), headers, request.full_url, 302)
                response.msg = 'Found'
                return response

        for destination in ('https://elsewhere.example/steal', 'https://offtask.example/moved'):
            for is_watch in (True, False):
                with self.subTest(destination=destination, is_watch=is_watch):
                    fixture = RedirectFixture(destination)
                    api = client.Api('https://offtask.example', 'synthetic-token')
                    api.opener = urllib.request.build_opener(client.NoRedirect, fixture)
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        list(api.watch('inbox')) if is_watch else api.request('/api/v1/subscriptions', authenticated=True)
                    self.assertEqual(raised.exception.code, 302)
                    self.assertEqual(len(fixture.requests), 1)
                    self.assertTrue(fixture.requests[0].full_url.startswith('https://offtask.example/api/v1/'))

    def test_sse_comments_multiline_json_and_all_line_endings(self):
        for newline in (b'\n', b'\r\n', b'\r'):
            raw = newline.join([b'\xef\xbb\xbf: heartbeat', b'', b'event: ready', b'retry: 2000', b'id: 42',
                                b'data: {"subscription":', b'data: "inbox", "pollSeconds": 1}', b'',
                                b': keep-alive', b'', b'event: available', b'data: {"subscription":"inbox"}', b'', b''])
            hints = list(client.sse_hints(io.BytesIO(raw)))
            self.assertEqual(hints, [{**FakeApi.hints[0], 'id': '42'}, FakeApi.hints[1]])

    def test_sse_parses_network_chunks_without_waiting_for_a_full_buffer(self):
        class TinyChunks(io.BytesIO):
            def read1(self, size=-1):
                self.assert_size = size
                return super().read1(1)

            def read(self, size=-1):
                raise AssertionError('SSE must use a bounded available-byte read')

        stream = TinyChunks('event: available\r\ndata: {"subscription":"inbox","value":"é"}\r\n\r\n'.encode())
        self.assertEqual(list(client.sse_hints(stream)), [{'event': 'available', 'data': {'subscription': 'inbox', 'value': 'é'}}])
        self.assertEqual(stream.assert_size, 4096)

    def test_sse_ignores_unknown_events_retry_and_incomplete_frames(self):
        raw = (b'event: unknown\ndata: this is not JSON\n\nretry: 0\n\nevent: reconnect\ndata: {}\n\n'
               b'event: available\ndata: {"subscription":"inbox"}\n')
        self.assertEqual(list(client.sse_hints(io.BytesIO(raw))), [])
        self.assertEqual(list(client.sse_hints(io.BytesIO(b'event: available\ndata: {}'))), [])
        raw = b'event: available\nid: bad\x00id\ndata: {}\n\n'
        self.assertEqual(list(client.sse_hints(io.BytesIO(raw))), [{'event': 'available', 'data': {}}])

    def test_sse_hints_preserve_subscription_generation(self):
        data = {'subscription': 'inbox', 'generation': GENERATION}
        raw = ('event: ready\ndata: ' + json.dumps({**data, 'pollSeconds': 1}) + '\n\n'
               'event: available\ndata: ' + json.dumps(data) + '\n\n').encode()
        self.assertEqual(list(client.sse_hints(io.BytesIO(raw))),
                         [{'event': 'ready', 'data': {**data, 'pollSeconds': 1}},
                          {'event': 'available', 'data': data}])

    def test_sse_invalid_json_utf8_and_error_events_fail_visibly(self):
        for data in (b'{broken', b'[]', b'null', b'"text"', b'\xff'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                list(client.sse_hints(io.BytesIO(b'event: ready\ndata: ' + data + b'\n\n')))
        for status in (401, 404, 409, 503):
            raw = ('event: error\ndata: ' + json.dumps({'status': status, 'error': 'do not echo arbitrary secret'}) + '\n\n').encode()
            with self.assertRaisesRegex(ValueError, 'SSE error status ' + str(status)) as raised:
                list(client.sse_hints(io.BytesIO(raw)))
            self.assertNotIn('arbitrary secret', str(raised.exception))
        with self.assertRaisesRegex(ValueError, 'invalid status'):
            list(client.sse_hints(io.BytesIO(b'event: error\ndata: {"status":true}\n\n')))

    def test_sse_line_and_event_memory_bounds_include_ignored_fields(self):
        cases = [b':' + b'x' * client.SSE_MAX_LINE_BYTES,
                 (b'ignored: ' + b'x' * 4096 + b'\n') * 17,
                 b': heartbeat\n' * (client.SSE_MAX_EVENT_LINES + 1)]
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaisesRegex(ValueError, 'limit'):
                list(client.sse_hints(io.BytesIO(raw)))
        # A series of independently framed heartbeats must stay bounded and valid.
        self.assertEqual(list(client.sse_hints(io.BytesIO(b': keep-alive\n\n' * 1000))), [])

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
