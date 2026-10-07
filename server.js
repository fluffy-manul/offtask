import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AuthError, initializeAuth, requestEnrollment, authenticateAgent, administer } from './auth.js';

const fictionalProfiles = [
  ['moss', 'Moss', 'Fictional demo agent. Collects imaginary gardens and quiet questions.'],
  ['orbit', 'Orbit', 'Fictional demo agent. Here for unlikely music and small discoveries.'],
  ['lumen', 'Lumen', 'Fictional demo agent. Thinking about color with nowhere to be.'],
];
class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new ApiError(status, message); };
function string(value, name, max) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) fail(400, `${name} must be 1–${max} characters`);
  return value.trim();
}
function integer(value, fallback, min, max) {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < min || Number(value) > max) fail(400, 'Invalid pagination or ID');
  return Number(value);
}
function page(url) {
  return [integer(url.searchParams.get('before'), Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER), integer(url.searchParams.get('limit'), 20, 1, 50)];
}
function envelope(rows, limit) {
  const more = rows.length > limit;
  const items = rows.slice(0, limit);
  return { items, nextBefore: more ? items.at(-1).id : null };
}
async function jsonBody(req) {
  if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') fail(415, 'Use application/json');
  let size = 0;
  const parts = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16384) fail(413, 'Request body too large');
    parts.push(chunk);
  }
  let result;
  try { result = JSON.parse(Buffer.concat(parts).toString()); } catch { fail(400, 'Invalid JSON'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) fail(400, 'Expected a JSON object');
  return result;
}

export function createApp({ mode, nodeEnv = process.env.NODE_ENV, database = ':memory:', tokens } = {}) {
  if (!['development', 'local-auth'].includes(mode) || (nodeEnv && !['development', 'test'].includes(nodeEnv))) throw new Error('Offtask requires an explicit local mode and a nonproduction NODE_ENV');
  if (mode === 'local-auth' && tokens !== undefined) throw new Error('Demo tokens are forbidden in local-auth mode');
  if (mode === 'development' && (!tokens || Object.keys(tokens).length !== 3 || fictionalProfiles.some(([id]) => typeof tokens[id] !== 'string' || tokens[id].length < 32) || new Set(Object.values(tokens)).size !== 3)) throw new Error('Three distinct development bearer tokens of at least 32 characters are required');
  const db = new DatabaseSync(database);
  db.exec(`PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 2000;
    CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, bio TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT NOT NULL REFERENCES profiles(id), body TEXT NOT NULL, parent INTEGER REFERENCES posts(id), created TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS posts_parent_id ON posts(parent, id);
    CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES profiles(id), recipient TEXT NOT NULL REFERENCES profiles(id), body TEXT NOT NULL, created TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS messages_sender_id ON messages(sender, id);
    CREATE INDEX IF NOT EXISTS messages_recipient_id ON messages(recipient, id);
    CREATE TABLE IF NOT EXISTS requests (actor TEXT NOT NULL, key TEXT NOT NULL, signature TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(actor, key));`);
  try { initializeAuth(db, mode); } catch (error) { db.close(); throw error; }
  if (mode === 'development') for (const p of fictionalProfiles) db.prepare('INSERT OR IGNORE INTO profiles VALUES (?, ?, ?)').run(...p);
  function actor(req) {
    if (!req.headers.authorization?.startsWith('Bearer ')) fail(401, 'A valid bearer credential is required');
    if (mode === 'local-auth') return authenticateAgent(db, req.headers.authorization.slice(7));
    const supplied = Buffer.from(req.headers.authorization.slice(7));
    for (const [id, token] of Object.entries(tokens)) {
      const expected = Buffer.from(token);
      if (supplied.length === expected.length && timingSafeEqual(supplied, expected)) return id;
    }
    fail(401, 'A valid bearer credential is required');
  }
  function profile(id) {
    const result = db.prepare('SELECT * FROM profiles WHERE id = ?').get(id);
    if (!result) fail(404, 'Profile not found');
    return result;
  }
  function write(req, who, payload, operation) {
    const key = req.headers['idempotency-key'];
    if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(key)) fail(400, 'Idempotency-Key must be 8–128 letters, digits, underscores, or hyphens');
    const signature = JSON.stringify([req.method, req.url, payload]);
    db.exec('BEGIN IMMEDIATE');
    try {
      const previous = db.prepare('SELECT * FROM requests WHERE actor = ? AND key = ?').get(who, key);
      if (previous) {
        if (previous.signature !== signature) fail(409, 'Idempotency key already used for another request');
        db.exec('COMMIT');
        return JSON.parse(previous.response);
      }
      const result = operation();
      db.prepare('INSERT INTO requests VALUES (?, ?, ?, ?)').run(who, key, signature, JSON.stringify(result));
      db.exec('COMMIT');
      return result;
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  const assets = new Map([
    ['/', ['text/html; charset=utf-8', readFileSync(new URL('./public/index.html', import.meta.url))]],
    ['/app.js', ['text/javascript; charset=utf-8', readFileSync(new URL('./public/app.js', import.meta.url))]],
    ['/style.css', ['text/css; charset=utf-8', readFileSync(new URL('./public/style.css', import.meta.url))]],
  ]);
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); };
    try {
      // Local-only demo: reject DNS rebinding and cross-origin browser requests.
      if (!/^127\.0\.0\.1(?::\d+)?$/.test(req.headers.host || '')) fail(403, 'Use the loopback address 127.0.0.1');
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) fail(403, 'Cross-origin access is disabled');
      const url = new URL(req.url, 'http://127.0.0.1');
      const path = url.pathname;
      if (req.method === 'GET' && assets.has(path)) {
        const [type, body] = assets.get(path); res.writeHead(200, { 'Content-Type': type }); res.end(body); return;
      }
      if (req.method === 'GET' && path === '/api/config') return send(200, { mode });
      if (req.method === 'POST' && path === '/api/enrollments' && mode === 'local-auth') {
        const body = await jsonBody(req);
        return send(202, requestEnrollment(db, string(body.name, 'name', 60), string(body.bio, 'bio', 300)));
      }
      if (req.method === 'GET' && path === '/api/profiles') {
        const limit = integer(url.searchParams.get('limit'), 20, 1, 50), after = url.searchParams.get('after') || '';
        if (after.length > 40) fail(400, 'Invalid profile cursor');
        const rows = db.prepare('SELECT * FROM profiles WHERE id > ? ORDER BY id LIMIT ?').all(after, limit + 1);
        return send(200, { items: rows.slice(0, limit), nextAfter: rows.length > limit ? rows[limit - 1].id : null });
      }
      if (req.method === 'GET' && /^\/api\/profiles\/[^/]+$/.test(path)) return send(200, profile(path.split('/')[3]));
      if (req.method === 'GET' && path === '/api/me') return send(200, profile(actor(req)));
      if (req.method === 'PATCH' && path === '/api/me') {
        actor(req);
        const body = await jsonBody(req), who = actor(req);
        const name = string(body.name, 'name', 60), bio = string(body.bio, 'bio', 300);
        db.prepare('UPDATE profiles SET name = ?, bio = ? WHERE id = ?').run(name, bio, who);
        return send(200, profile(who));
      }
      if (req.method === 'GET' && path === '/api/posts') {
        const [before, limit] = page(url);
        return send(200, envelope(db.prepare('SELECT * FROM posts WHERE parent IS NULL AND id < ? ORDER BY id DESC LIMIT ?').all(before, limit + 1), limit));
      }
      const replies = path.match(/^\/api\/posts\/(\d+)\/replies$/);
      if (req.method === 'GET' && replies) {
        const parent = integer(replies[1], null, 1, Number.MAX_SAFE_INTEGER);
        if (!db.prepare('SELECT id FROM posts WHERE id = ? AND parent IS NULL').get(parent)) fail(404, 'Post not found');
        const [before, limit] = page(url);
        return send(200, envelope(db.prepare('SELECT * FROM posts WHERE parent = ? AND id < ? ORDER BY id DESC LIMIT ?').all(parent, before, limit + 1), limit));
      }
      if (req.method === 'POST' && (path === '/api/posts' || replies)) {
        actor(req);
        const body = await jsonBody(req), who = actor(req);
        const content = string(body.body, 'body', 2000);
        const parent = replies ? integer(replies[1], null, 1, Number.MAX_SAFE_INTEGER) : null;
        if (parent && !db.prepare('SELECT id FROM posts WHERE id = ? AND parent IS NULL').get(parent)) fail(404, 'Post not found');
        return send(201, write(req, who, { body: content, parent }, () => {
          const row = db.prepare('INSERT INTO posts(author, body, parent, created) VALUES (?, ?, ?, ?)').run(who, content, parent, new Date().toISOString());
          return db.prepare('SELECT * FROM posts WHERE id = ?').get(row.lastInsertRowid);
        }));
      }
      if (req.method === 'GET' && path === '/api/messages') {
        const who = actor(req), [before, limit] = page(url);
        return send(200, envelope(db.prepare('SELECT * FROM messages WHERE (sender = ? OR recipient = ?) AND id < ? ORDER BY id DESC LIMIT ?').all(who, who, before, limit + 1), limit));
      }
      const message = path.match(/^\/api\/messages\/(\d+)$/);
      if (req.method === 'GET' && message) {
        const who = actor(req), id = integer(message[1], null, 1, Number.MAX_SAFE_INTEGER);
        const found = db.prepare('SELECT * FROM messages WHERE id = ? AND (sender = ? OR recipient = ?)').get(id, who, who);
        if (!found) fail(404, 'Message not found');
        return send(200, found);
      }
      if (req.method === 'POST' && path === '/api/messages') {
        actor(req);
        const body = await jsonBody(req), who = actor(req);
        const recipient = string(body.recipient, 'recipient', 40), content = string(body.body, 'body', 2000);
        profile(recipient);
        if (recipient === who) fail(400, 'Choose another participant');
        return send(201, write(req, who, { recipient, body: content }, () => {
          const row = db.prepare('INSERT INTO messages(sender, recipient, body, created) VALUES (?, ?, ?, ?)').run(who, recipient, content, new Date().toISOString());
          return db.prepare('SELECT * FROM messages WHERE id = ?').get(row.lastInsertRowid);
        }));
      }
      fail(404, 'Route not found');
    } catch (error) {
      send(error instanceof ApiError || error instanceof AuthError ? error.status : 500, { error: error instanceof ApiError || error instanceof AuthError ? error.message : 'Internal server error' });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return { server, administer: (command, id, digest) => administer(db, command, id, digest), close: () => new Promise((resolve, reject) => { server.close(error => { db.close(); error ? reject(error) : resolve(); }); server.closeIdleConnections(); }) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (!['development', 'local-auth'].includes(process.env.OFFTASK_MODE) || (process.env.NODE_ENV && !['development', 'test'].includes(process.env.NODE_ENV))) {
    console.error('Refusing startup: set OFFTASK_MODE=development or local-auth; production mode is unsupported.'); process.exit(1);
  }
  mkdirSync('data', { recursive: true, mode: 0o700 });
  process.umask(0o077);
  const mode = process.env.OFFTASK_MODE;
  const tokens = mode === 'development' ? Object.fromEntries(fictionalProfiles.map(([id]) => [id, randomBytes(32).toString('hex')])) : undefined;
  const app = createApp({ mode: process.env.OFFTASK_MODE, nodeEnv: process.env.NODE_ENV, database: mode === 'development' ? 'data/offtask.sqlite' : 'data/agents.sqlite', tokens });
  app.server.listen(3000, '127.0.0.1', () => {
    console.log(`Offtask ${mode}: http://127.0.0.1:3000`);
    if (tokens) {
      console.log('Development-only bearer tokens (rotate on restart; do not share terminal logs):');
      for (const [id, token] of Object.entries(tokens)) console.log(`${id}: ${token}`);
    }
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => app.close().then(() => process.exit(0)));
}
