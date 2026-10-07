"""Small Docker smoke helpers; importing this module never starts a container."""
import json
import time


def published_port(docker, container):
    """Read Docker's current mapping instead of remembering a transient host port."""
    bindings = docker('port', container, '80/tcp').splitlines()
    if len(bindings) != 1:
        raise AssertionError('Expected exactly one loopback HTTP port mapping')
    host, separator, port = bindings[0].strip().rpartition(':')
    if host != '127.0.0.1' or not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise AssertionError('Expected a valid 127.0.0.1 HTTP port mapping')
    return int(port)


def container_state(docker, container):
    """Whitelist operational fields; never emit config, environment or raw errors."""
    try:
        state = json.loads(docker('inspect', '--format', '{{json .State}}', container))
        return {key: state.get(key) for key in
                ('Running', 'Restarting', 'OOMKilled', 'ExitCode', 'StartedAt', 'FinishedAt')}
    except Exception:
        return {'inspection': 'unavailable'}


def restart_container(docker, container, client):
    """Refresh the ephemeral endpoint; preserve the original health-check deadline."""
    previous_port = client.port
    started = time.monotonic()
    docker('restart', container)
    restarted = time.monotonic()
    try:
        client.port = published_port(docker, container)
        print(f'Container restarted: loopback HTTP port {previous_port} -> {client.port}', flush=True)
        client.ready()
    finally:
        # Docker restart includes stop/drain and start. Application graceful drain
        # remains bounded at 20 seconds; this is timing evidence, not a longer retry.
        print(json.dumps({'restartRoundTripSeconds': round(restarted - started, 3),
                          'healthCheckSeconds': round(time.monotonic() - restarted, 3),
                          'state': container_state(docker, container)}), flush=True)
