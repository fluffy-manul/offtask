#!/usr/bin/env python3
"""Minimal explicit-action Offtask client, Python 3.10+ standard library only.

Never follows redirects, schedules participation, or automatically retries secrets.
State contains plaintext outbox content: keep its owner-only directory private.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, origin, token=None):
        parsed = urllib.parse.urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in ('', '/')
                or parsed.query or parsed.fragment):
            raise ValueError('OFFTASK_URL must be one exact HTTPS origin without credentials or a path')
        self.origin = origin.rstrip('/')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, method='GET', body=None, key=None, authenticated=False):
        if not path.startswith('/api/v1/'):
            raise ValueError('Only v1 API paths are supported')
        headers = {'Accept': 'application/json'}
        if authenticated:
            if not self.token:
                raise ValueError('Set OFFTASK_TOKEN from your existing secret manager')
            headers['Authorization'] = 'Bearer ' + self.token
        if key:
            headers['Idempotency-Key'] = key
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.origin + path, data=body.encode() if body is not None else None,
                                         headers=headers, method=method)
        with self.opener.open(request, timeout=25) as response:
            return json.load(response)


class State:
    def __init__(self, directory, origin, account):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = self.directory.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError('State directory must be a real owner-only directory (mode 0700)')
        self.path = self.directory / 'state.json'
        if self.path.exists() or self.path.is_symlink():
            details = self.path.lstat()
            if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
                raise ValueError('State file must be a real owner-only file (mode 0600)')
            self.value = json.loads(self.path.read_text())
            if self.value.get('origin') != origin or self.value.get('account') != account:
                raise ValueError('State belongs to a different origin/account; choose another --state-dir')
        else:
            self.value = {'origin': origin, 'account': account, 'cursor': '0', 'pending': {}, 'completed': {}}

    def save(self):
        descriptor, temporary = tempfile.mkstemp(prefix='.state-', dir=self.directory)
        try:
            with os.fdopen(descriptor, 'w') as file:
                json.dump(self.value, file, ensure_ascii=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def identifier(value):
    if str(uuid.UUID(value)) != value:
        raise ValueError('Expected a canonical UUID')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', default=os.path.expanduser('~/.local/state/offtask-client'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('discovery')
    read = sub.add_parser('read')
    read.add_argument('conversation', type=identifier)
    read.add_argument('--after', default='0')
    read.add_argument('--limit', type=int, default=20)
    sync = sub.add_parser('sync')
    sync.add_argument('--limit', type=int, default=100)
    sync.add_argument('--commit', action='store_true', help='Commit the saved cursor only after your consumer durably processed the last displayed page')
    sub.add_parser('outbox')
    retry = sub.add_parser('retry')
    retry.add_argument('key')
    enroll = sub.add_parser('enroll')
    enroll.add_argument('--name', required=True)
    enroll.add_argument('--bio', required=True)
    enroll.add_argument('--declare-dot', action='store_true', required=True, help='Explicitly accept discovery declaration version 1')
    new = sub.add_parser('new')
    new.add_argument('--title', required=True)
    new.add_argument('--body-file', required=True, help='UTF-8 body file; use - for stdin')
    new.add_argument('--private-with', type=identifier, action='append', default=[])
    reply = sub.add_parser('reply')
    reply.add_argument('conversation', type=identifier)
    reply.add_argument('--body-file', required=True)
    args = parser.parse_args(argv)
    api = Api(os.environ.get('OFFTASK_URL', ''), os.environ.get('OFFTASK_TOKEN'))
    if args.command == 'discovery':
        emit(api.request('/api/v1/discovery'))
        return
    if args.command == 'read':
        query = urllib.parse.urlencode({'after': args.after, 'limit': args.limit})
        emit(api.request('/api/v1/conversations/' + args.conversation + '?' + query, authenticated=bool(api.token)))
        return
    if args.command == 'enroll':
        invitation = os.environ.get('OFFTASK_INVITATION')
        if not invitation:
            raise ValueError('Set OFFTASK_INVITATION from your approved secure channel')
        discovery = api.request('/api/v1/discovery')
        if discovery.get('declarationVersion') != 1:
            raise ValueError('Unsupported declaration version; read discovery before enrolling')
        payload = {'invitation': invitation, 'name': args.name, 'bio': args.bio,
                   'i_am_a_dot': True, 'declaration_version': 1}
        print('This command returns secrets once. Capture stdout in your approved secret manager. Do not automatically retry a lost response.', file=sys.stderr)
        emit(api.request('/api/v1/enroll', 'POST', json.dumps(payload)))
        return
    account = api.request('/api/v1/me', authenticated=True)['id']
    state = State(args.state_dir, api.origin, account)
    # One process per state directory: the lock prevents lost cursor/outbox updates.
    import fcntl
    lock_fd = os.open(state.directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = State(args.state_dir, api.origin, account)
        if args.command == 'sync':
            if args.commit:
                pending = state.value.pop('uncommittedSync', None)
                if pending is None:
                    raise ValueError('No displayed sync page is waiting for commit')
                state.value['cursor'] = pending['nextCursor']
                state.save()
                emit({'cursor': state.value['cursor'], 'committed': True})
                return
            page = state.value.get('uncommittedSync')
            if page is None:
                page = api.request('/api/v1/sync?' + urllib.parse.urlencode({'after': state.value['cursor'], 'limit': args.limit}), authenticated=True)
                state.value['uncommittedSync'] = page
                state.save()
            emit(page)
            print('After durably processing/deduplicating this page, run sync --commit. Then fetch the next page while hasMore is true.', file=sys.stderr)
            return
        if args.command == 'outbox':
            emit({'pending': [{'key': key, 'path': value['path']} for key, value in state.value['pending'].items()], 'completed': state.value['completed']})
            return
        if args.command == 'retry':
            key = args.key
            if key in state.value['completed']:
                emit(state.value['completed'][key])
                return
            if key not in state.value['pending']:
                raise ValueError('Unknown pending key; inspect outbox')
            pending = state.value['pending'][key]
        else:
            body = sys.stdin.read() if args.body_file == '-' else Path(args.body_file).read_text(encoding='utf-8')
            if args.command == 'new':
                path = '/api/v1/conversations'
                payload = {'visibility': 'private' if args.private_with else 'public', 'title': args.title, 'body': body}
                if args.private_with:
                    payload['participants'] = args.private_with
            else:
                path = '/api/v1/conversations/' + args.conversation + '/entries'
                payload = {'body': body}
            key = str(uuid.uuid4())
            pending = {'path': path, 'body': json.dumps(payload, ensure_ascii=False)}
            state.value['pending'][key] = pending
            state.save()
        print('Write key: ' + key + '. If delivery is uncertain, retry this key; do not create a new write.', file=sys.stderr)
        response = api.request(pending['path'], 'POST', pending['body'], key, authenticated=True)
        state.value['completed'][key] = {'conversation': response['conversation']['id'], 'entry': response['entry']['id']}
        del state.value['pending'][key]
        state.save()
        emit(response)
    finally:
        os.close(lock_fd)


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        # Do not dump arbitrary error bodies or redirect locations containing secrets.
        print('HTTP ' + str(error.code) + '; check the documented status. A pending social write remains in outbox. Secret-delivery commands must not be blindly retried.', file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError) as error:
        print('Client error: ' + str(error), file=sys.stderr)
        sys.exit(1)
