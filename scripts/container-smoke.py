"""Validate a built public-preview image; creates no external resources."""
import http.client
import json
import subprocess
import sys
import time

image = sys.argv[1] if len(sys.argv) > 1 else 'offtask-preview'

def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()

assert docker('image', 'inspect', '--format', '{{.Config.User}}', image) == '10001:10001'
container = docker('run', '-d', '--read-only', '--cap-drop=ALL', '--cap-add=NET_BIND_SERVICE',
                   '--sysctl', 'net.ipv4.ip_unprivileged_port_start=1024',
                   '-p', '127.0.0.1::80', '-e', 'PUBLIC_ORIGIN=https://offtask.example', image)
try:
    port = int(docker('port', container, '80/tcp').rsplit(':', 1)[1])
    def request(path, method='GET', host='offtask.example', origin=None):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        headers = {'Host': host}
        if origin:
            headers['Origin'] = origin
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        result = (response.status, body, dict(response.getheaders()))
        connection.close()
        return result
    for attempt in range(50):
        try:
            if request('/healthz', host='internal-probe')[0] == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    else:
        raise AssertionError('Container health check did not pass')
    status, body, headers = request('/api/posts', origin='https://offtask.example')
    assert status == 200 and len(json.loads(body)['items']) == 2
    assert request('/api/posts', host='evil.example')[0] == 403
    assert request('/api/posts', origin='https://evil.example')[0] == 403
    for path in ['/api/posts', '/api/messages', '/api/enrollments', '/api/me']:
        assert request(path, method='POST')[0] == 405
    for path in ['/api/messages', '/api/me', '/api/enrollments', '/admin.js']:
        assert request(path)[0] == 404
    assert request('/')[0] == 200
    assert 'moss:' not in docker('logs', container)
    print('Container smoke passed: nonroot port 80 with restricted low ports, read-only filesystem, health, fictional feed, host/origin checks, no writes/private routes/credentials.')
finally:
    docker('rm', '-f', container)

for env in [[], ['-e', 'PUBLIC_ORIGIN=http://offtask.example'],
            ['-e', 'OFFTASK_MODE=local-auth', '-e', 'NODE_ENV=test', '-e', 'PUBLIC_ORIGIN=https://offtask.example']]:
    result = subprocess.run(['docker', 'run', '--rm', *env, image], capture_output=True, text=True, timeout=15)
    assert result.returncode != 0, 'Unsafe startup configuration was accepted'
print('Container startup rejection checks passed.')
