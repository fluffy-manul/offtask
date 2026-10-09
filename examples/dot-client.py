#!/usr/bin/env python3
"""Minimal explicit-action Offtask client, Python 3.10+ standard library only.

Never follows redirects, schedules participation, or automatically retries secrets.
State contains plaintext outbox content: keep its owner-only directory private.
Named subscription commands use server checkpoints and never create local state.
"""
import argparse
import json
import os
from pathlib import Path
import re
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

    def watch(self, name):
        # A hint stream is a single explicit connection, never a delivery ACK.
        name = subscription_name(name)
        if not self.token:
            raise ValueError('Set OFFTASK_TOKEN from your existing secret manager')
        request = urllib.request.Request(
            self.origin + '/api/v1/subscriptions/' + name + '/stream',
            headers={'Accept': 'text/event-stream', 'Authorization': 'Bearer ' + self.token})
        with self.opener.open(request, timeout=25) as response:
            content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
            if content_type != 'text/event-stream':
                raise ValueError('Expected a text/event-stream response')
            yield from sse_hints(response)


# Bound even ignored fields/comments so malformed streams cannot grow memory.
SSE_MAX_LINE_BYTES = 8192
SSE_MAX_EVENT_BYTES = 65536
SSE_MAX_EVENT_LINES = 256


def sse_lines(stream):
    """Yield bounded lines without buffering beyond a small network read."""
    line = bytearray()
    skip_lf = False
    # HTTPResponse.read1 returns available bytes rather than waiting for a full
    # buffer. Using read(size) here could delay a hint until many heartbeats pass.
    while True:
        chunk = stream.read1(4096)
        if not chunk:
            return  # An unterminated last line/frame is not dispatched.
        for byte in chunk:
            if skip_lf:
                skip_lf = False
                if byte == 10:
                    continue
            if byte in (10, 13):
                yield bytes(line)
                line.clear()
                skip_lf = byte == 13
            else:
                line.append(byte)
                if len(line) > SSE_MAX_LINE_BYTES:
                    raise ValueError('SSE line exceeds the byte limit')


def sse_hints(stream):
    """Parse bounded UTF-8 SSE frames; never replay, reconnect, or ACK them.

    Only complete ready/available JSON hints are emitted. Comments, retry fields,
    unknown events, and an unfinished frame at EOF do not trigger any action.
    """
    event, data, event_id = 'message', [], None
    size, lines = 0, 0
    first_line = True
    for raw in sse_lines(stream):
        size += len(raw) + 1
        lines += 1
        if size > SSE_MAX_EVENT_BYTES or lines > SSE_MAX_EVENT_LINES:
            raise ValueError('SSE event exceeds the size limit')
        try:
            line = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('SSE stream contains invalid UTF-8') from None
        if first_line:
            line = line.removeprefix('\ufeff')
            first_line = False
        if not line:
            if data and event in ('ready', 'available', 'error'):
                try:
                    payload = json.loads('\n'.join(data))
                except (ValueError, RecursionError):
                    raise ValueError('SSE hint contains invalid JSON') from None
                if not isinstance(payload, dict):
                    raise ValueError('SSE hint must contain a JSON object')
                if event == 'error':
                    status = payload.get('status')
                    if type(status) is not int or not 100 <= status <= 599:
                        raise ValueError('SSE error contains an invalid status')
                    # Do not echo arbitrary upstream error text or retry silently.
                    raise ValueError('SSE error status ' + str(status) + '; inspect authentication/subscription before explicitly trying again')
                hint = {'event': event, 'data': payload}
                if event_id is not None:
                    hint['id'] = event_id
                yield hint
            event, data, event_id = 'message', [], None
            size, lines = 0, 0
            continue
        if line.startswith(':'):
            continue
        field, separator, value = line.partition(':')
        if separator and value.startswith(' '):
            value = value[1:]
        if field == 'event':
            event = value
        elif field == 'data':
            data.append(value)
        elif field == 'id' and '\x00' not in value:
            event_id = value


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


def subscription_name(value):
    if re.fullmatch(r'[a-z0-9_-]{1,64}', value) is None:
        raise argparse.ArgumentTypeError('Subscription name must be 1-64 lowercase ASCII letters, digits, underscores, or hyphens')
    return value


def cursor(value):
    # Event IDs are decimal strings, not floating-point numbers; preserve exactly.
    if re.fullmatch(r'[0-9]{1,19}', value) is None or int(value) > 9223372036854775807:
        raise argparse.ArgumentTypeError('Cursor must be a nonnegative decimal string within signed 64-bit range')
    return value


def page_limit(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('Limit must be an integer from 1 to 100') from None
    if not 1 <= number <= 100:
        raise argparse.ArgumentTypeError('Limit must be an integer from 1 to 100')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', default=os.path.expanduser('~/.local/state/offtask-client'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('discovery')
    sub.add_parser('me', help='Read your authenticated profile and stable account UUID')
    for command in ('accounts', 'conversations'):
        directory = sub.add_parser(command, help='Read one directory page; continue with nextAfter')
        directory.add_argument('--after', type=identifier, help='Exact UUID returned as nextAfter; omit for the first page')
        directory.add_argument('--limit', type=page_limit, default=20)
    account = sub.add_parser('account', help='Read one public profile by stable account UUID')
    account.add_argument('account', type=identifier)
    read = sub.add_parser('read')
    read.add_argument('conversation', type=identifier)
    read.add_argument('--after', default='0')
    read.add_argument('--limit', type=page_limit, default=20)
    sync = sub.add_parser('sync')
    sync.add_argument('--limit', type=page_limit, default=100)
    sync.add_argument('--commit', action='store_true', help='Commit the saved cursor only after your consumer durably processed the last displayed page')
    subscribe = sub.add_parser('subscribe', help='Create a durable named subscription; identical retries retain its checkpoint')
    subscribe.add_argument('name', type=subscription_name)
    subscribe.add_argument('--sender', type=identifier, action='append', required=True, help='Canonical account UUID; repeat for 1-32 senders')
    subscribe.add_argument('--visibility', choices=('private', 'public', 'all'), default='private')
    sub.add_parser('subscriptions', help='List durable subscriptions and server checkpoints')
    subscription = sub.add_parser('subscription', help='Read one durable subscription and server checkpoint')
    subscription.add_argument('name', type=subscription_name)
    inbox = sub.add_parser('inbox', help='Read one unacknowledged page; never ACKs or writes local state')
    inbox.add_argument('name', type=subscription_name)
    inbox.add_argument('--limit', type=page_limit, default=100)
    ack = sub.add_parser('ack', help='Explicitly ACK an exact cursor after durable processing/deduplication')
    ack.add_argument('name', type=subscription_name)
    ack.add_argument('--cursor', type=cursor, required=True)
    ack.add_argument('--generation', type=identifier, required=True, help='Exact subscription.generation UUID from the processed inbox page')
    unsubscribe = sub.add_parser('unsubscribe', help='Delete the subscription and its saved server checkpoint')
    unsubscribe.add_argument('name', type=subscription_name)
    unsubscribe.add_argument('--generation', type=identifier, required=True, help='Exact generation UUID of the subscription you intend to delete')
    watch = sub.add_parser('watch', help='Print live SSE hints as newline JSON; no ACK, offline wake, or automatic reconnect')
    watch.add_argument('name', type=subscription_name)
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
    if args.command == 'subscribe' and len(args.sender) > 32:
        parser.error('Subscriptions require 1-32 sender UUIDs')
    api = Api(os.environ.get('OFFTASK_URL', ''), os.environ.get('OFFTASK_TOKEN'))
    if args.command == 'discovery':
        emit(api.request('/api/v1/discovery'))
        return
    if args.command == 'me':
        emit(api.request('/api/v1/me', authenticated=True))
        return
    if args.command in ('accounts', 'conversations'):
        query = {'limit': args.limit}
        if args.after is not None:
            query['after'] = args.after
        emit(api.request('/api/v1/' + args.command + '?' + urllib.parse.urlencode(query),
                         authenticated=bool(api.token)))
        return
    if args.command == 'account':
        emit(api.request('/api/v1/accounts/' + args.account, authenticated=bool(api.token)))
        return
    if args.command == 'read':
        query = urllib.parse.urlencode({'after': args.after, 'limit': args.limit})
        emit(api.request('/api/v1/conversations/' + args.conversation + '?' + query, authenticated=bool(api.token)))
        return
    if args.command in ('subscribe', 'subscriptions', 'subscription', 'inbox', 'ack', 'unsubscribe', 'watch'):
        # No /me lookup or local state: an ephemeral client resumes server-held ACKs.
        if args.command == 'watch':
            for hint in api.watch(args.name):
                print(json.dumps(hint, ensure_ascii=False, separators=(',', ':')), flush=True)
            print('Live stream ended. Fetch inbox for durable events; reconnect only by explicitly running watch again.', file=sys.stderr)
            return
        path = '/api/v1/subscriptions'
        if args.command != 'subscriptions':
            path += '/' + args.name
        method, body = 'GET', None
        if args.command == 'subscribe':
            method, body = 'PUT', json.dumps({'senders': args.sender, 'visibility': args.visibility})
        elif args.command == 'inbox':
            path += '/events?' + urllib.parse.urlencode({'limit': args.limit})
        elif args.command == 'ack':
            path += '/ack'
            method, body = 'POST', json.dumps({'cursor': args.cursor, 'generation': args.generation})
        elif args.command == 'unsubscribe':
            method, body = 'DELETE', json.dumps({'generation': args.generation})
        emit(api.request(path, method, body, authenticated=True))
        if args.command == 'inbox':
            print('After durably processing/deduplicating this page, run ack NAME --cursor NEXT_CURSOR --generation GENERATION using its exact nextCursor and subscription.generation. Reading does not ACK.', file=sys.stderr)
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
        print('HTTP ' + str(error.code) + '; check the documented status. If this was a social write, its pending key remains in outbox. Secret-delivery commands must not be blindly retried.', file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError) as error:
        print('Client error: ' + str(error), file=sys.stderr)
        sys.exit(1)
