import test from 'node:test';
import { request as httpRequest } from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server.js';
const tokens = { moss: 'm'.repeat(64), orbit: 'o'.repeat(64), lumen: 'l'.repeat(64) };
async function fixture(t, database) {
  const app = createApp({ mode: 'development', nodeEnv: 'test', tokens, database });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const base = `http://127.0.0.1:${app.server.address().port}`;
  async function request(path, { actor, method = 'GET', body, key = 'request-key-0001', headers = {} } = {}) {
    const response = await fetch(base + path, { method, headers: { ...(actor ? { Authorization: `Bearer ${tokens[actor]}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json', 'Idempotency-Key': key } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, body: await response.json(), headers: response.headers };
  }
  return { request, base };
}
test('startup fails closed outside explicitly enabled development', () => {
  for (const options of [{}, { mode: 'production' }, { mode: 'development', nodeEnv: 'production' }, { mode: 'development', nodeEnv: 'staging' }]) assert.throws(() => createApp({ ...options, tokens }));
  assert.throws(() => createApp({ mode: 'development', tokens: { moss: 'short' } }));
});
test('public profiles, identity proof, and profile ownership', async t => {
  const { request } = await fixture(t);
  assert.equal((await request('/api/profiles')).body.items.length, 3);
  assert.equal((await request('/api/me')).status, 401);
  assert.equal((await request('/api/me', { headers: { Authorization: tokens.moss } })).status, 401);
  assert.equal((await request('/api/me', { actor: 'orbit' })).body.id, 'orbit');
  assert.equal((await request('/api/me', { actor: 'moss', method: 'PATCH', body: { id: 'orbit', name: 'Fern', bio: 'A fictional garden admirer.' } })).body.id, 'moss');
  assert.equal((await request('/api/profiles/orbit')).body.name, 'Orbit');
});
test('public posts, chronological pagination, replies, and retry idempotency', async t => {
  const { request } = await fixture(t);
  const body = { body: '<img src=x onerror=alert(1)>', author: 'orbit' };
  assert.equal((await request('/api/posts', { method: 'POST', body })).status, 401);
  const first = await request('/api/posts', { actor: 'moss', method: 'POST', body });
  assert.equal(first.status, 201); assert.equal(first.body.author, 'moss');
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body })).body.id, first.body.id);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body: { body: 'Different' } })).status, 409);
  const second = await request('/api/posts', { actor: 'orbit', method: 'POST', body: { body: 'Another thought' } });
  const page = (await request('/api/posts?limit=1')).body;
  assert.equal(page.items[0].id, second.body.id); assert.equal(page.nextBefore, second.body.id);
  assert.equal((await request(`/api/posts?before=${page.nextBefore}&limit=1`)).body.items[0].body, body.body);
  const reply = await request(`/api/posts/${first.body.id}/replies`, { actor: 'lumen', method: 'POST', body: { body: 'A reply' } });
  assert.equal(reply.status, 201);
  assert.equal((await request(`/api/posts/${first.body.id}/replies`)).body.items[0].parent, first.body.id);
  assert.equal((await request(`/api/posts/${reply.body.id}/replies`)).status, 404);
  assert.equal((await request('/api/posts')).body.items.length, 2);
});
test('DM authorization rejects anonymous and third-party IDOR and ignores forged sender', async t => {
  const { request } = await fixture(t);
  const options = { actor: 'moss', method: 'POST', body: { recipient: 'orbit', sender: 'lumen', body: 'Private hello' } };
  const message = await request('/api/messages', options);
  assert.equal(message.status, 201); assert.equal(message.body.sender, 'moss');
  assert.equal((await request('/api/messages', options)).body.id, message.body.id);
  for (const actor of ['moss', 'orbit']) {
    assert.equal((await request(`/api/messages/${message.body.id}`, { actor })).status, 200);
    assert.equal((await request('/api/messages', { actor })).body.items.length, 1);
  }
  assert.equal((await request(`/api/messages/${message.body.id}`, { actor: 'lumen' })).status, 404);
  assert.equal((await request('/api/messages', { actor: 'lumen' })).body.items.length, 0);
  for (const path of ['/api/messages', `/api/messages/${message.body.id}`]) assert.equal((await request(path)).status, 401);
  assert.equal((await request('/api/messages', { method: 'POST', body: options.body })).status, 401);
  assert.equal((await request('/api/messages?sender=moss&recipient=orbit', { actor: 'lumen' })).body.items.length, 0);
  assert.equal((await request('/api/posts')).body.items.length, 0);
});
test('validation, pagination bounds, media type, size, and browser boundaries', async t => {
  const { request, base } = await fixture(t);
  for (const query of ['limit=0', 'limit=51', 'limit=-1', 'limit=abc', 'before=0', 'before=9007199254740992']) assert.equal((await request(`/api/posts?${query}`)).status, 400);
  for (const body of [{ body: '' }, { body: '   ' }, { body: 4 }, { body: 'a'.repeat(2001) }, []]) assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body })).status, 400);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body: { body: 'Hello' }, key: 'bad' })).status, 400);
  assert.equal((await request('/api/messages', { actor: 'moss', method: 'POST', body: { recipient: 'missing', body: 'Hello' } })).status, 404);
  assert.equal((await request('/api/messages', { actor: 'moss', method: 'POST', body: { recipient: 'moss', body: 'Hello' } })).status, 400);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body: { body: 'a'.repeat(17000) } })).status, 413);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body: {}, headers: { 'Content-Type': 'text/plain' } })).status, 415);
  const invalid = await fetch(base + '/api/posts', { method: 'POST', headers: { Authorization: `Bearer ${tokens.moss}`, 'Content-Type': 'application/json' }, body: '{' });
  assert.equal(invalid.status, 400);
  assert.equal((await request('/api/profiles', { headers: { Origin: 'https://evil.example' } })).status, 403);
  const rebindingStatus = await new Promise((resolve, reject) => {
    const req = httpRequest(base + '/api/profiles', { headers: { Host: 'evil.example' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.end();
  });
  assert.equal(rebindingStatus, 403);
  const html = await fetch(base);
  assert.equal(html.status, 200); assert.match(html.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(html.headers.get('cache-control'), 'no-store');
  assert.equal((await fetch(base + '/server.js')).status, 404);
});
test('SQLite survives restart, including DM authorization and idempotency', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'offtask-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const database = join(dir, 'db.sqlite');
  async function run(callback) {
    const app = createApp({ mode: 'development', tokens, database });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    try { await callback(`http://127.0.0.1:${app.server.address().port}`); } finally { await app.close(); }
  }
  const headers = { Authorization: `Bearer ${tokens.moss}`, 'Content-Type': 'application/json', 'Idempotency-Key': 'persistent-key' };
  const init = { method: 'POST', headers, body: JSON.stringify({ recipient: 'orbit', body: 'Still here' }) };
  let id;
  await run(async base => { id = (await (await fetch(base + '/api/messages', init)).json()).id; });
  await run(async base => {
    assert.equal((await (await fetch(base + '/api/messages', init)).json()).id, id);
    assert.equal((await fetch(base + `/api/messages/${id}`, { headers: { Authorization: `Bearer ${tokens.lumen}` } })).status, 404);
    assert.equal((await (await fetch(base + '/api/messages', { headers })).json()).items.length, 1);
  });
});

test('imported startup honors production environment when nodeEnv is omitted', () => {
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    assert.throws(() => createApp({ mode: 'development', tokens }), /nonproduction/);
  } finally { if (previous === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous; }
});

test('DM pagination stays participant-scoped and retries cannot cross actors or endpoints', async t => {
  const { request } = await fixture(t);
  const send = (actor, recipient, key, body = 'A note') => request('/api/messages', { actor, method: 'POST', key, body: { recipient, body } });
  const first = await send('moss', 'orbit', 'shared-retry-key');
  const unrelated = await send('orbit', 'lumen', 'shared-retry-key');
  const last = await send('orbit', 'moss', 'second-retry-key');
  const page = (await request('/api/messages?limit=1', { actor: 'moss' })).body;
  assert.equal(page.items[0].id, last.body.id);
  const older = (await request(`/api/messages?limit=1&before=${page.nextBefore}`, { actor: 'moss' })).body;
  assert.equal(older.items[0].id, first.body.id); assert.equal(older.nextBefore, null);
  assert.equal((await request(`/api/messages/${unrelated.body.id}`, { actor: 'moss' })).status, 404);
  assert.equal((await send('moss', 'lumen', 'shared-retry-key')).status, 409);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', key: 'shared-retry-key', body: { body: 'A note' } })).status, 409);
  const concurrent = await Promise.all(Array.from({ length: 5 }, () => send('moss', 'orbit', 'concurrent-key')));
  assert.ok(concurrent.every(result => result.status === 201 && result.body.id === concurrent[0].body.id));
  for (const query of ['limit=51', 'before=-1', 'before=1%20OR%201=1']) assert.equal((await request(`/api/messages?${query}`, { actor: 'moss' })).status, 400);
});

test('SQL metacharacters stay data and forged identity hints cannot authenticate', async t => {
  const { request } = await fixture(t);
  const attack = "'; DROP TABLE profiles; --";
  const profile = await request('/api/me', { actor: 'moss', method: 'PATCH', body: { name: 'Orbit', bio: attack } });
  assert.equal(profile.body.id, 'moss'); assert.equal(profile.body.bio, attack);
  assert.equal((await request('/api/profiles')).body.items.length, 3);
  assert.equal((await request('/api/messages', { actor: 'moss', method: 'POST', body: { recipient: "orbit' OR '1'='1", body: 'Hello' } })).status, 404);
  assert.equal((await request('/api/messages?actor=moss', { headers: { 'X-Agent-Id': 'moss', Cookie: 'actor=moss', Authorization: 'Bearer wrong' } })).status, 401);
  assert.equal((await request('/api/posts', { actor: 'moss', method: 'POST', body: { body: attack } })).body.body, attack);
});

test('restart preserves public content and profile edits while rotated credentials revoke old access', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'offtask-rotate-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const database = join(dir, 'db.sqlite');
  async function run(credentials, callback) {
    const app = createApp({ mode: 'development', tokens: credentials, database });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    try { await callback(`http://127.0.0.1:${app.server.address().port}`); } finally { await app.close(); }
  }
  let id;
  await run(tokens, async base => {
    const headers = { Authorization: `Bearer ${tokens.moss}`, 'Content-Type': 'application/json', 'Idempotency-Key': 'restart-post-key' };
    await fetch(base + '/api/me', { method: 'PATCH', headers, body: JSON.stringify({ name: 'Fern', bio: 'Still fictional' }) });
    id = (await (await fetch(base + '/api/posts', { method: 'POST', headers, body: JSON.stringify({ body: 'Persistent thought' }) })).json()).id;
    await fetch(base + `/api/posts/${id}/replies`, { method: 'POST', headers: { ...headers, 'Idempotency-Key': 'restart-reply-key' }, body: JSON.stringify({ body: 'Persistent reply' }) });
  });
  const rotated = Object.fromEntries(Object.keys(tokens).map(id => [id, tokens[id].toUpperCase()]));
  await run(rotated, async base => {
    assert.equal((await fetch(base + '/api/me', { headers: { Authorization: `Bearer ${tokens.moss}` } })).status, 401);
    assert.equal((await (await fetch(base + '/api/me', { headers: { Authorization: `Bearer ${rotated.moss}` } })).json()).name, 'Fern');
    assert.equal((await (await fetch(base + '/api/posts')).json()).items[0].body, 'Persistent thought');
    assert.equal((await (await fetch(base + `/api/posts/${id}/replies`)).json()).items[0].body, 'Persistent reply');
  });
});
