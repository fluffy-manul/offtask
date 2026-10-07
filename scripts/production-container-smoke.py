"""Disposable Docker production verification with real, hostname-verified PG TLS.

Requires Docker and OpenSSL. Builds no image and contacts no deployed app.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location('production_smoke', Path(__file__).with_name('production-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
image = sys.argv[1] if len(sys.argv) > 1 else 'offtask'
network = 'offtask-smoke-' + uuid.uuid4().hex
resources = []


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def openssl(*args):
    subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


assert docker('image', 'inspect', '--format', '{{.Config.User}}', image) == '10001:10001'
config = json.loads(docker('image', 'inspect', image))[0]['Config']
assert not config.get('ExposedPorts'), 'Port routing must be configured by the deployment platform'
assert 'OFFTASK_MODE=production' in config['Env']
assert config['Cmd'] == ['--production']

with tempfile.TemporaryDirectory(prefix='offtask-container-') as temporary:
    directory = Path(temporary)
    ca, server, key = [directory / name for name in ('ca.crt', 'server.crt', 'server.key')]
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Offtask synthetic test CA', '-keyout', str(directory / 'ca.key'),
            '-out', str(ca), '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=database',
            '-keyout', str(key), '-out', str(directory / 'server.csr'))
    (directory / 'server.ext').write_text('subjectAltName=DNS:database\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', str(directory / 'server.csr'), '-CA', str(ca),
            '-CAkey', str(directory / 'ca.key'), '-CAcreateserial', '-days', '1',
            '-out', str(server), '-extfile', str(directory / 'server.ext'))
    ca.chmod(0o644)
    docker('network', 'create', network)
    try:
        database = docker('run', '-d', '--network', network, '--network-alias', 'database',
                          '--network-alias', 'wrong-database',
                          '-e', 'POSTGRES_USER=offtask_test', '-e', 'POSTGRES_PASSWORD=synthetic-ci-only',
                          '-e', 'POSTGRES_DB=offtask_test',
                          '-v', str(directory) + ':/fixture:ro', '--entrypoint', '/bin/sh',
                          'postgres:17-bookworm', '-c',
                          'cp /fixture/server.crt /tmp/server.crt && cp /fixture/server.key /tmp/server.key && '
                          'chown postgres:postgres /tmp/server.crt /tmp/server.key && chmod 600 /tmp/server.key && '
                          'exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on '
                          '-c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key')
        resources.append(database)
        for _ in range(100):
            check = subprocess.run(['docker', 'exec', database, 'pg_isready', '-h', '127.0.0.1', '-U', 'offtask_test', '-d', 'offtask_test'], capture_output=True)
            if check.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError('PostgreSQL container did not become ready')

        url = 'postgresql://offtask_test:synthetic-ci-only@database:5432/offtask_test?sslmode=disable'
        common = ['--network', network, '--read-only', '--cap-drop=ALL',
                  '--cap-add=NET_BIND_SERVICE', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=1024',
                  '-v', str(ca) + ':/run/offtask-test-ca.crt:ro',
                  '-e', 'PUBLIC_ORIGIN=https://offtask.example',
                  '-e', 'DATABASE_URL=' + url, '-e', 'DATABASE_CA_CERT=/run/offtask-test-ca.crt']
        app = docker('run', '-d', *common, '-p', '127.0.0.1::80', image)
        resources.append(app)
        port = int(docker('port', app, '80/tcp').rsplit(':', 1)[1])
        client = smoke.Client(port)
        client.ready()
        # The URL deliberately requests sslmode=disable; the app must override it.
        tls = docker('exec', database, 'psql', '-U', 'offtask_test', '-d', 'offtask_test', '-Atc',
                     "SELECT bool_and(s.ssl) FROM pg_stat_activity a JOIN pg_stat_ssl s USING(pid) WHERE a.application_name='offtask'")
        assert tls == 't', 'Production database connections did not all use TLS'

        def admin(*args):
            return json.loads(docker('run', '--rm', *common, '--entrypoint', '/usr/local/bin/offtask-admin', image, *args))

        def restart():
            docker('restart', app)
            client.ready()

        smoke.protocol_suite(client, admin, restart)
        logs = docker('logs', app)
        assert 'offtask_recovery_' not in logs and 'offtask_invite_' not in logs
        # Verified TLS must reject a trusted certificate with the wrong hostname,
        # an absent trust root, and the test-only bypass in NODE_ENV=production.
        for additions in [
            ['-e', 'DATABASE_URL=' + url.replace('@database:', '@wrong-database:')],
            ['-e', 'DATABASE_CA_CERT=/run/missing-ca.crt'],
            ['-e', 'OFFTASK_DATABASE_INSECURE=true'],
            ['-e', 'PUBLIC_ORIGIN=http://offtask.example'],
            ['-e', 'OFFTASK_MODE=local-auth'],
        ]:
            result = subprocess.run(['docker', 'run', '--rm', *common, *additions, image], capture_output=True, text=True, timeout=20)
            assert result.returncode != 0, 'Unsafe production startup configuration was accepted'
        result = subprocess.run(['docker', 'run', '--rm', image], capture_output=True, text=True, timeout=20)
        assert result.returncode != 0, 'Production image accepted missing database/origin configuration'
        print('Production container smoke passed: TLS and hostname verification, insecure override rejection, nonroot restricted port 80, no EXPOSE, read-only root, bundled admin CLI, and restart persistence.')
    except Exception:
        for resource in resources:
            subprocess.run(['docker', 'logs', resource], check=False)
        raise
    finally:
        for resource in reversed(resources):
            subprocess.run(['docker', 'rm', '-f', '-v', resource], check=False, stdout=subprocess.DEVNULL)
        subprocess.run(['docker', 'network', 'rm', network], check=False, stdout=subprocess.DEVNULL)
