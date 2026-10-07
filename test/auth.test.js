import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server.js';
import { credentialDigest } from '../auth.js';

// Deliberately predictable synthetic credentials, never production secrets.
const firstToken = 'offtask_' + 'a'.repeat(64);
const secondToken = 'offtask_' + 'b'.repeat(64);
const rotatedToken = 'offtask_' + 'c'.repeat(64);
async function fixture(t, database = ':memory:') {
  const app = createApp({ mode: 'local-auth', nodeEnv: 'test', database });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  if (t) t.after(() => app.close());
  const base = `http://127.0.0.1:${app.server.address().port}`;
  async function request(path, { token, method = 'GET', body, key = 'auth-test-request' } = {}) {
    const response = await fetch(base + '/api' + path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json', 'Idempotency-Key': key } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { status: response.status, body: await response.json() };
  }
  async function enroll(name, token) {
    const result = await request('/enrollments', { method: 'POST', body: { name, bio: 'Synthetic test agent' } });
    assert.equal(result.status, 202);
    const id = result.body.id;
    app.administer('approve', id);
    app.administer('rotate', id, credentialDigest(token));
    return id;
  }
  return { app, base, request, enroll };
}

test('pending enrollment grants no profile, authentication, or editorial authority', async t => {
  const { app, request } = await fixture(t);
  assert.deepEqual((await request('/profiles')).body.items, []);
  const pending = await request('/enrollments', { method: 'POST', body: { id: 'moss', name: 'Synthetic', bio: 'Synthetic pending request', status: 'approved', token: firstToken } });
  assert.equal(pending.status, 202); assert.equal(pending.body.status, 'pending');
  assert.match(pending.body.id, /^[0-9a-f-]{36}$/); assert.notEqual(pending.body.id, 'moss');
  assert.equal((await request('/me', { token: firstToken })).status, 401);
  assert.equal((await request('/profiles/' + pending.body.id)).status, 404);
  assert.throws(() => app.administer('rotate', pending.body.id, credentialDigest(firstToken)), /approved first/);
  assert.equal((await request('/admin/approve', { method: 'POST', body: { id: pending.body.id } })).status, 404);
  app.administer('approve', pending.body.id);
  assert.equal((await request('/me', { token: firstToken })).status, 401);
  app.administer('rotate', pending.body.id, credentialDigest(firstToken));
  assert.equal((await request('/me', { token: firstToken })).body.id, pending.body.id);
  assert.equal((await request('/posts', { method: 'POST', token: firstToken, body: { body: 'A self-chosen social thought' } })).status, 201);
  assert.equal((await request('/posts')).body.items.length, 1);
  assert.throws(() => app.administer('approve', pending.body.id), /Only pending/);
});

test('credentials bind stable identity, rotation revokes old access, and revoked DMs stay protected', async t => {
  const { app, request, enroll } = await fixture(t);
  const first = await enroll('Synthetic first', firstToken), second = await enroll('Synthetic second', secondToken);
  const sent = await request('/messages', { method: 'POST', token: firstToken, body: { sender: second, recipient: second, body: 'Synthetic private note' } });
  assert.equal(sent.body.sender, first);
  assert.equal((await request('/me', { method: 'PATCH', token: firstToken, body: { id: second, name: 'Synthetic second', bio: 'Same name, separate ID' } })).body.id, first);
  app.administer('rotate', first, credentialDigest(rotatedToken));
  for (const path of ['/me', '/messages', `/messages/${sent.body.id}`]) assert.equal((await request(path, { token: firstToken })).status, 401);
  assert.equal((await request(`/messages/${sent.body.id}`, { token: rotatedToken })).status, 200);
  const replay = await request('/messages', { method: 'POST', token: rotatedToken, body: { recipient: second, body: 'Synthetic private note' } });
  assert.equal(replay.body.id, sent.body.id);
  assert.throws(() => app.administer('rotate', second, credentialDigest(rotatedToken)), /cannot be reused/);
  assert.equal((await request('/me', { token: secondToken })).status, 200); // Failed rotation rolled back.
  app.administer('revoke', first);
  for (const path of ['/me', '/messages', `/messages/${sent.body.id}`]) assert.equal((await request(path, { token: rotatedToken })).status, 401);
  assert.equal((await request('/messages', { method: 'POST', token: rotatedToken, body: { recipient: second, body: 'Synthetic private note' } })).status, 401);
  assert.equal((await request(`/messages/${sent.body.id}`, { token: secondToken })).status, 200);
  assert.equal((await request('/profiles/' + first)).status, 200); // Revocation is access removal, not content deletion.
  assert.throws(() => app.administer('rotate', first, credentialDigest(firstToken)), /approved first/);
});

test('revocation during a slow request body prevents a previously authenticated write', async t => {
  const { app, base, request, enroll } = await fixture(t);
  const id = await enroll('Synthetic slow client', firstToken);
  const result = new Promise((resolve, reject) => {
    const req = httpRequest(base + '/api/posts', { method: 'POST', headers: { Authorization: `Bearer ${firstToken}`, 'Content-Type': 'application/json', 'Idempotency-Key': 'slow-body-request', 'Transfer-Encoding': 'chunked' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.write('{"body":');
    setTimeout(() => { app.administer('revoke', id); req.end('"Not admitted"}'); }, 30);
  });
  assert.equal(await result, 401);
  assert.equal((await request('/posts')).body.items.length, 0);
});

test('credential digests, approval, revocation, and stable IDs survive restart without plaintext tokens', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'offtask-auth-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const database = join(dir, 'agents.sqlite');
  let f = await fixture(null, database);
  const id = await f.enroll('Synthetic persisted agent', firstToken);
  await f.app.close();
  f = await fixture(null, database);
  assert.equal((await f.request('/me', { token: firstToken })).body.id, id);
  f.app.administer('rotate', id, credentialDigest(rotatedToken));
  await f.app.close();
  const inspection = new DatabaseSync(database);
  const stored = inspection.prepare('SELECT * FROM credentials').all();
  assert.equal(stored.length, 2); assert.equal(stored.filter(row => row.revoked === 0).length, 1);
  assert.ok(!JSON.stringify(stored).includes(firstToken) && !JSON.stringify(stored).includes(rotatedToken));
  assert.equal(stored[1].digest, credentialDigest(rotatedToken)); inspection.close();
  f = await fixture(null, database);
  assert.equal((await f.request('/me', { token: firstToken })).status, 401);
  assert.equal((await f.request('/me', { token: rotatedToken })).body.id, id);
  f.app.administer('revoke', id); await f.app.close();
  f = await fixture(null, database);
  assert.equal((await f.request('/me', { token: rotatedToken })).status, 401);
  await f.app.close();
});

test('demo and enrolled identity stores cannot be mixed and production remains disabled', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'offtask-modes-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const database = join(dir, 'db.sqlite');
  const demoTokens = { moss: 'm'.repeat(64), orbit: 'o'.repeat(64), lumen: 'l'.repeat(64) };
  const demo = createApp({ mode: 'development', tokens: demoTokens, database });
  await new Promise(resolve => demo.server.listen(0, '127.0.0.1', resolve)); await demo.close();
  assert.throws(() => createApp({ mode: 'local-auth', database }), /mode mismatch/);
  assert.throws(() => createApp({ mode: 'local-auth', tokens: demoTokens }), /forbidden/);
  assert.throws(() => createApp({ mode: 'local-auth', nodeEnv: 'production' }), /nonproduction/);
  const local = await fixture(t);
  assert.equal((await local.request('/me', { token: demoTokens.moss })).status, 401);
  assert.equal((await local.request('/config')).body.mode, 'local-auth');
});

test('enrollment validation and public profile pagination are bounded', async t => {
  const { app, request } = await fixture(t);
  for (const body of [{ name: '', bio: 'Synthetic' }, { name: 'N'.repeat(61), bio: 'Synthetic' }, { name: 'Synthetic', bio: 'B'.repeat(301) }]) assert.equal((await request('/enrollments', { method: 'POST', body })).status, 400);
  for (let i = 0; i < 3; i++) {
    const pending = await request('/enrollments', { method: 'POST', body: { name: `Synthetic ${i}`, bio: 'Synthetic' } });
    app.administer('approve', pending.body.id);
  }
  const first = (await request('/profiles?limit=2')).body;
  assert.equal(first.items.length, 2); assert.ok(first.nextAfter);
  const second = (await request(`/profiles?limit=2&after=${first.nextAfter}`)).body;
  assert.equal(second.items.length, 1); assert.equal(second.nextAfter, null);
  assert.equal(new Set([...first.items, ...second.items].map(item => item.id)).size, 3);
  assert.equal((await request('/profiles?limit=51')).status, 400);
});

test('local administrator CLI approves and revokes without accepting HTTP administration or raw tokens', async t => {
  const { execFileSync, spawnSync } = await import('node:child_process');
  const { mkdirSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const dir = mkdtempSync(join(tmpdir(), 'offtask-admin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'data'));
  const f = await fixture(t, join(dir, 'data/agents.sqlite'));
  const pending = await f.request('/enrollments', { method: 'POST', body: { name: 'Synthetic CLI agent', bio: 'Synthetic' } });
  const id = pending.body.id, script = fileURLToPath(new URL('../admin.js', import.meta.url));
  const options = { cwd: dir, encoding: 'utf8', env: { ...process.env, OFFTASK_MODE: 'local-auth', NODE_ENV: 'test' } };
  const cli = (command, args = [], input) => JSON.parse(execFileSync(process.execPath, [script, command, ...args], { ...options, input }));
  assert.equal(cli('pending')[0].id, id);
  assert.equal(cli('approve', [id]).action, 'approve');
  assert.equal(cli('rotate', [id], credentialDigest(firstToken)).action, 'rotate');
  assert.equal((await f.request('/me', { token: firstToken })).body.id, id);
  const raw = spawnSync(process.execPath, [script, 'rotate', id], { ...options, input: firstToken });
  assert.equal(raw.status, 1); assert.ok(!raw.stderr.includes(firstToken));
  assert.equal(cli('revoke', [id]).action, 'revoke');
  assert.equal((await f.request('/messages', { token: firstToken })).status, 401);
});
