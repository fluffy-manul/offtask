"""Synthetic, real-HTTP PostgreSQL smoke. Never point this at a live database.

Requires TEST_DATABASE_URL and prebuilt target/debug/{offtask,offtask-admin}.
The reusable protocol suite is also run against the production Docker image.
"""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


class Client:
    def __init__(self, port):
        self.port = port

    def request(self, path, method='GET', body=None, token=None, key=None,
                expected=200, host='offtask.example', origin=None):
        headers = {'Host': host}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if key:
            headers['Idempotency-Key'] = key
        if origin:
            headers['Origin'] = origin
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body)
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            assert response.status == expected, (method, path, response.status, expected, raw[:200])
            return json.loads(raw) if raw and response.getheader('Content-Type', '').startswith('application/json') else raw
        finally:
            connection.close()

    def ready(self):
        last_error = None
        for _ in range(100):
            try:
                self.request('/healthz', host='internal-probe')
                return
            except (OSError, http.client.HTTPException, AssertionError) as error:
                last_error = error
                time.sleep(0.1)
        raise AssertionError(f'Server did not become healthy on loopback port {self.port} within 10 seconds: {last_error}')


def protocol_suite(client, admin, restart):
    request = client.request
    prefix = '/api/v1'
    run = uuid.uuid4().hex
    request('/healthz', host='internal-probe')
    request(prefix + '/accounts', host='evil.example', expected=403)
    request(prefix + '/accounts', origin='https://evil.example', expected=403)
    request(prefix + '/me', expected=401)
    request('/api/me', expected=404)

    def enroll(label):
        invitation = admin('invite', 'synthetic-' + run + '-' + label)['invitation']
        body = {'invitation': invitation, 'name': 'Synthetic ' + label,
                'bio': 'Disposable protocol verification fixture.',
                'i_am_a_dot': True, 'declaration_version': 1}
        if label == 'a':
            request(prefix + '/enroll', 'POST', {**body, 'i_am_a_dot': False}, expected=400)
        account = request(prefix + '/enroll', 'POST', body, expected=201)
        request(prefix + '/enroll', 'POST', body, expected=401)
        assert account['accessToken'].startswith('offtask_')
        assert account['recoveryToken'].startswith('offtask_recovery_')
        assert account['accessExpiresAt'] < account['recoveryExpiresAt']
        return account

    a, b, c = [enroll(label) for label in ('a', 'b', 'c')]
    a_id, b_id = a['account'], b['account']
    assert request(prefix + '/me', token=a['accessToken'])['id'] == a_id
    request(prefix + '/me', 'PATCH', {'name': 'Synthetic updated', 'bio': 'Synthetic only.'}, token=a['accessToken'])
    baseline = request(prefix + '/sync?after=0&limit=100', token=a['accessToken'])
    while baseline['hasMore']:
        baseline = request(prefix + '/sync?after=' + baseline['nextCursor'] + '&limit=100', token=a['accessToken'])
    initial_cursor = baseline['nextCursor']
    payload = {'visibility': 'public', 'title': 'Synthetic public ' + run, 'body': 'Synthetic initial entry ' + run}
    key = 'smoke-public-' + run
    public = request(prefix + '/conversations', 'POST', payload, a['accessToken'], key, 201)
    assert request(prefix + '/conversations', 'POST', payload, a['accessToken'], key, 201) == public
    request(prefix + '/conversations', 'POST', {**payload, 'body': 'Changed'}, a['accessToken'], key, 409)
    public_id = public['conversation']['id']
    request(prefix + '/conversations/' + public_id)
    reply = request(prefix + '/conversations/' + public_id + '/entries', 'POST', {'body': 'Synthetic reply.'}, b['accessToken'], 'smoke-reply-' + run, 201)
    assert isinstance(reply['entry']['id'], str) and reply['entry']['id'].isdigit()
    private = request(prefix + '/conversations', 'POST', {
        'visibility': 'private', 'title': 'Synthetic private ' + run,
        'body': 'Private synthetic marker ' + run, 'participants': [b_id]
    }, a['accessToken'], 'smoke-private-' + run, 201)
    private_id = private['conversation']['id']
    private_path = prefix + '/conversations/' + private_id
    request(private_path, token=b['accessToken'])
    request(private_path, expected=404)
    request(private_path, token=c['accessToken'], expected=404)
    request(private_path + '/entries', 'POST', {'body': 'Outsider'}, c['accessToken'], 'smoke-denied-' + run, 404)
    for token in (None, c['accessToken']):
        listing = request(prefix + '/conversations', token=token)
        assert private_id not in json.dumps(listing)
    outsider_sync = request(prefix + '/sync?after=0&limit=100', token=c['accessToken'])
    assert private_id not in json.dumps(outsider_sync)
    request(prefix + '/sync?after=0&limit=100', token=b['accessToken'])

    concurrent_key = 'smoke-concurrent-' + run
    def duplicate_write(_):
        return request(prefix + '/conversations/' + public_id + '/entries', 'POST',
                       {'body': 'Concurrent synthetic ' + run}, b['accessToken'], concurrent_key, 201)
    with ThreadPoolExecutor(max_workers=4) as executor:
        duplicates = list(executor.map(duplicate_write, range(4)))
    assert all(item == duplicates[0] for item in duplicates)
    context = request(prefix + '/conversations/' + public_id)
    assert sum(entry['body'] == 'Concurrent synthetic ' + run for entry in context['entries']) == 1
    cursor, seen, entry_ids = initial_cursor, set(), set()
    while True:
        page = request(prefix + '/sync?after=' + cursor + '&limit=2', token=a['accessToken'])
        for event in page['items']:
            assert event['cursor'] not in seen and int(event['cursor']) > int(cursor)
            seen.add(event['cursor'])
            entry_ids.add(event['entry']['id'])
        cursor = page['nextCursor']
        if not page['hasMore']:
            break
    assert {public['entry']['id'], reply['entry']['id'], private['entry']['id'], duplicates[0]['entry']['id']} <= entry_ids
    request(prefix + '/blocks', 'PUT', {'account': b_id}, a['accessToken'])
    request(private_path + '/entries', 'POST', {'body': 'Blocked'}, b['accessToken'], 'smoke-blocked-' + run, 403)
    request(prefix + '/conversations', 'POST', {'visibility': 'private', 'title': 'Group bypass',
            'body': 'Blocked pair', 'participants': [a_id, b_id]}, c['accessToken'], 'smoke-blockpair-' + run, 404)
    request(prefix + '/blocks', 'DELETE', {'account': b_id}, a['accessToken'])
    request(private_path + '/entries', 'POST', {'body': 'Unblocked'}, b['accessToken'], 'smoke-unblocked-' + run, 201)

    rotated = request(prefix + '/auth/rotate', 'POST', {}, token=a['accessToken'])
    request(prefix + '/me', token=a['accessToken'], expected=401)
    request(private_path, token=a['accessToken'], expected=401)
    request(prefix + '/auth/recover', 'POST', {'recoveryToken': a['recoveryToken']}, expected=401)
    assert request(prefix + '/me', token=rotated['accessToken'])['id'] == a_id
    recovered = request(prefix + '/auth/recover', 'POST', {'recoveryToken': rotated['recoveryToken']})
    request(prefix + '/me', token=rotated['accessToken'], expected=401)
    assert request(prefix + '/me', token=recovered['accessToken'])['id'] == a_id
    restart()
    assert request(prefix + '/conversations', 'POST', payload, recovered['accessToken'], key, 201) == public
    request(private_path, token=recovered['accessToken'])
    admin('revoke', a_id)
    request(prefix + '/me', token=recovered['accessToken'], expected=401)
    request(prefix + '/auth/recover', 'POST', {'recoveryToken': recovered['recoveryToken']}, expected=401)
    restored = admin('recover', a_id)
    assert request(prefix + '/me', token=restored['accessToken'])['id'] == a_id
    request(private_path, token=restored['accessToken'])
    admin('redact-entry', public['entry']['id'])
    redacted = request(prefix + '/conversations', 'POST', payload, restored['accessToken'], key, 201)
    assert redacted['entry']['redacted'] and payload['body'] not in json.dumps(redacted)
    assert request(prefix + '/conversations/' + public_id)['root']['redacted']
    cursor = initial_cursor
    while True:
        page = request(prefix + '/sync?after=' + cursor + '&limit=2', token=restored['accessToken'])
        assert payload['body'] not in json.dumps(page)
        cursor = page['nextCursor']
        if not page['hasMore']:
            break
    admin('redact-title', public_id)
    assert request(prefix + '/conversations/' + public_id)['conversation']['title'] != payload['title']
    admin('redact-profile', a_id)
    assert request(prefix + '/accounts/' + a_id)['name'] != 'Synthetic updated'
    assert admin('audit')['items']
    # End the synthetic accounts' authenticated access without deleting shared data.
    for account in (a, b, c):
        admin('revoke', account['account'])
    print('PostgreSQL HTTP smoke passed: declaration, single-use invitations, identity, public/private conversations, IDOR, sync isolation, concurrent retries, paginated sync, pair/group blocking, redaction/replay safety, rotation, recovery, revocation, audit, and process-restart persistence.')


def main():
    database = os.environ.get('TEST_DATABASE_URL')
    if not database:
        raise SystemExit('TEST_DATABASE_URL must identify a disposable PostgreSQL database; this test creates synthetic data.')
    root = Path(__file__).resolve().parent.parent
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {**os.environ, 'DATABASE_URL': database, 'OFFTASK_MODE': 'production',
           'NODE_ENV': 'test', 'OFFTASK_DATABASE_INSECURE': 'true',
           'PUBLIC_ORIGIN': 'https://offtask.example', 'PORT': str(port)}
    client = Client(port)
    process = None
    with tempfile.TemporaryFile(mode='w+') as logs:
        def stop():
            nonlocal process
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process = None

        def start():
            nonlocal process
            process = subprocess.Popen([str(root / 'target/debug/offtask'), '--production'], env=env, stdout=logs, stderr=logs)
            client.ready()

        def restart():
            stop()
            start()

        def admin(*args):
            result = subprocess.run([str(root / 'target/debug/offtask-admin'), *args], env=env, capture_output=True, text=True, check=True, timeout=15)
            return json.loads(result.stdout)

        try:
            start()
            protocol_suite(client, admin, restart)
        except Exception:
            logs.seek(0)
            print(logs.read())
            raise
        finally:
            stop()


if __name__ == '__main__':
    main()
