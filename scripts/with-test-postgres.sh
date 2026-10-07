#!/bin/sh
# Start a disposable, loopback-only synthetic PostgreSQL cluster for one command.
# Usage: PG_BIN=/path/to/postgres/bin scripts/with-test-postgres.sh cargo test --locked -- --include-ignored
set -eu
if [ "$#" -eq 0 ]; then
    echo 'Usage: scripts/with-test-postgres.sh COMMAND [ARGUMENT ...]' >&2
    exit 2
fi
if [ -z "${PG_BIN:-}" ]; then
    if command -v pg_config >/dev/null 2>&1; then
        PG_BIN=$(pg_config --bindir)
    else
        PG_BIN=/usr/lib/postgresql/17/bin
    fi
fi
for executable in initdb pg_ctl createdb; do
    if [ ! -x "$PG_BIN/$executable" ]; then
        echo "Missing $PG_BIN/$executable; install PostgreSQL 17 tools or set PG_BIN." >&2
        exit 2
    fi
done
work=$(mktemp -d "${TMPDIR:-/tmp}/offtask-postgres.XXXXXXXX")
cleanup() {
    "$PG_BIN/pg_ctl" -D "$work/data" -m immediate -w stop >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
"$PG_BIN/initdb" --no-locale --encoding=UTF8 --auth-local=trust --auth-host=trust \
    -U offtask_test -D "$work/data" > "$work/initdb.log"
# TCP-only also works in sandboxes that do not support Unix sockets.
if ! "$PG_BIN/pg_ctl" -D "$work/data" -l "$work/server.log" \
    -o "-h 127.0.0.1 -p $port -c unix_socket_directories=''" -w start >/dev/null; then
    cat "$work/server.log" >&2
    exit 1
fi
"$PG_BIN/createdb" -h 127.0.0.1 -p "$port" -U offtask_test offtask_test
export TEST_DATABASE_URL="postgresql://offtask_test@127.0.0.1:$port/offtask_test"
export NODE_ENV=test OFFTASK_DATABASE_INSECURE=true
"$@"
