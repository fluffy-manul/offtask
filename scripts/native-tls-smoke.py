#!/usr/bin/env python3
"""Verify production PostgreSQL TLS using a disposable native cluster.

Requires prebuilt target/debug/offtask-admin, PostgreSQL 17 tools and OpenSSL.
PG_BIN may select the PostgreSQL bin directory. No Docker, existing database,
production credentials, or external network access is used.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=20, **kwargs)


def checked(args, **kwargs):
    result = run(args, **kwargs)
    if result.returncode:
        raise AssertionError(f"{Path(args[0]).name} failed: {result.stderr}")
    return result.stdout.strip()


def main():
    pg_bin = os.environ.get('PG_BIN')
    if not pg_bin:
        pg_bin = checked(['pg_config', '--bindir']) if shutil.which('pg_config') else '/usr/lib/postgresql/17/bin'
    pg_bin = Path(pg_bin)
    admin = ROOT / 'target/debug/offtask-admin'
    for path in [admin, *(pg_bin / name for name in ('initdb', 'pg_ctl', 'createdb', 'psql'))]:
        if not path.is_file():
            raise SystemExit(f'Missing {path}; build the Rust binaries and install PostgreSQL 17 tools first.')
    if not shutil.which('openssl'):
        raise SystemExit('OpenSSL is required for the disposable certificate fixture.')
    # Do not inherit a real connection, certificate, credentials, or test bypass.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('PG', 'DATABASE_', 'OFFTASK_')) and key != 'TEST_DATABASE_URL'}
    env.update(OFFTASK_MODE='production', NODE_ENV='production')
    with tempfile.TemporaryDirectory(prefix='offtask-native-tls-') as temporary:
        work = Path(temporary)
        data, log = work / 'data', work / 'postgres.log'
        ca, key, certificate = [work / name for name in ('ca.crt', 'server.key', 'server.crt')]
        for label in ('ca', 'untrusted-ca'):
            checked(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                     '-subj', f'/CN=Offtask synthetic {label}', '-keyout', str(work / (label + '.key')),
                     '-out', str(work / (label + '.crt')), '-addext', 'basicConstraints=critical,CA:TRUE',
                     '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        checked(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
                 '-keyout', str(key), '-out', str(work / 'server.csr')])
        extension = work / 'server.ext'
        extension.write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
                             'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        checked(['openssl', 'x509', '-req', '-in', str(work / 'server.csr'), '-CA', str(ca),
                 '-CAkey', str(work / 'ca.key'), '-CAcreateserial', '-days', '1',
                 '-out', str(certificate), '-extfile', str(extension)])
        key.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        checked([str(pg_bin / 'initdb'), '--no-locale', '--encoding=UTF8', '--auth-local=trust',
                 '--auth-host=trust', '-U', 'offtask_test', '-D', str(data)], env=env)
        # Successful SQL is impossible without TLS. Authentication is synthetic,
        # loopback-only trust, unrelated to the certificate-verification checks.
        (data / 'pg_hba.conf').write_text('hostnossl all all 127.0.0.1/32 reject\n'
                                         'hostssl all all 127.0.0.1/32 trust\n')
        options = (f"-h 127.0.0.1 -p {port} -c unix_socket_directories='' -c ssl=on "
                   f"-c ssl_cert_file={certificate} -c ssl_key_file={key}")
        try:
            checked([str(pg_bin / 'pg_ctl'), '-D', str(data), '-l', str(log), '-o', options, '-w', 'start'], env=env)
            tls_env = {**env, 'PGSSLMODE': 'verify-full', 'PGSSLROOTCERT': str(ca)}
            connection = ['-h', 'localhost', '-p', str(port), '-U', 'offtask_test']
            checked([str(pg_bin / 'createdb'), *connection, 'offtask_test'], env=tls_env)
            tls = checked([str(pg_bin / 'psql'), *connection, '-d', 'offtask_test', '-Atc',
                           'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()'], env=tls_env)
            assert tls == 't', 'PostgreSQL fixture did not negotiate TLS'
            plaintext = run([str(pg_bin / 'psql'), *connection, '-d', 'offtask_test', '-Atc', 'SELECT 1'],
                            env={**env, 'PGSSLMODE': 'disable'})
            assert plaintext.returncode != 0, 'Fixture unexpectedly accepted plaintext SQL'
            url = f'postgresql://offtask_test@localhost:{port}/offtask_test?sslmode=disable'
            base = {**env, 'DATABASE_URL': url}

            def probe(label, additions, accepted):
                result = run([str(admin), 'migrate'], env={**base, **additions})
                assert (result.returncode == 0) == accepted, f'{label}: unexpected result: {result.stderr}'
                print(f'PASS: {label}', flush=True)

            probe('NODE_ENV=production overrides sslmode=disable with verified TLS (CA file)',
                  {'DATABASE_CA_CERT': str(ca)}, True)
            probe('inline PEM CA accepts the same hostname-verified TLS connection',
                  {'DATABASE_CA_CERT_PEM': ca.read_text()}, True)
            probe('trusted certificate with wrong hostname is rejected',
                  {'DATABASE_URL': url.replace('@localhost:', '@127.0.0.1:'), 'DATABASE_CA_CERT': str(ca)}, False)
            probe('existing but untrusted CA certificate is rejected',
                  {'DATABASE_CA_CERT': str(work / 'untrusted-ca.crt')}, False)
            probe('private test certificate is rejected without a configured trust root', {}, False)
            probe('missing CA file is rejected', {'DATABASE_CA_CERT': str(work / 'missing.crt')}, False)
            probe('conflicting file and PEM CA configuration is rejected',
                  {'DATABASE_CA_CERT': str(ca), 'DATABASE_CA_CERT_PEM': ca.read_text()}, False)
            probe('production rejects the test-only insecure transport bypass',
                  {'DATABASE_CA_CERT': str(ca), 'OFFTASK_DATABASE_INSECURE': 'true'}, False)
            print('Native PostgreSQL TLS smoke passed: plaintext impossible, verified file/PEM trust, wrong-host and untrusted-CA rejection, and production bypass rejection.')
        except Exception:
            if log.exists():
                print(log.read_text())
            raise
        finally:
            run([str(pg_bin / 'pg_ctl'), '-D', str(data), '-m', 'immediate', '-w', 'stop'], env=env)


if __name__ == '__main__':
    main()
