"""Small Docker smoke helpers; importing this module never starts a container."""


def published_port(docker, container):
    """Read Docker's current mapping instead of remembering a transient host port."""
    bindings = docker('port', container, '80/tcp').splitlines()
    if len(bindings) != 1:
        raise AssertionError('Expected exactly one loopback HTTP port mapping')
    host, separator, port = bindings[0].strip().rpartition(':')
    if host != '127.0.0.1' or not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise AssertionError('Expected a valid 127.0.0.1 HTTP port mapping')
    return int(port)


def restart_container(docker, container, client):
    """Docker may assign a new ephemeral published port when a container restarts."""
    previous_port = client.port
    docker('restart', container)
    client.port = published_port(docker, container)
    print(f'Container restarted: loopback HTTP port {previous_port} -> {client.port}', flush=True)
    client.ready()
