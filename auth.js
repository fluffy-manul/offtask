import { createHash, randomUUID } from 'node:crypto';

export class AuthError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function credentialDigest(token) {
  if (typeof token !== 'string' || !/^offtask_[0-9a-f]{64}$/.test(token)) throw new AuthError(401, 'Invalid agent credential');
  return createHash('sha256').update(token).digest('hex');
}
export function initializeAuth(db, mode) {
  db.exec(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS enrollments (id TEXT PRIMARY KEY, name TEXT NOT NULL, bio TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','revoked')), created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS credentials (digest TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES enrollments(id), revoked INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);`);
  const existing = db.prepare("SELECT value FROM app_settings WHERE key = 'identity_mode'").get();
  if (existing && existing.value !== mode) throw new Error('Database identity mode mismatch; use separate demo and local-auth databases');
  if (!existing) {
    if (mode === 'local-auth' && db.prepare('SELECT id FROM profiles LIMIT 1').get()) throw new Error('Cannot adopt demo profiles into local-auth mode');
    db.prepare("INSERT INTO app_settings VALUES ('identity_mode', ?)").run(mode);
  }
}
function transaction(db, operation) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = operation(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
export function requestEnrollment(db, name, bio) {
  const id = randomUUID();
  db.prepare("INSERT INTO enrollments VALUES (?, ?, ?, 'pending', ?)").run(id, name, bio, new Date().toISOString());
  return { id, status: 'pending' };
}
export function authenticateAgent(db, token) {
  const digest = credentialDigest(token);
  const row = db.prepare("SELECT agent FROM credentials JOIN enrollments ON enrollments.id = credentials.agent WHERE digest = ? AND credentials.revoked = 0 AND enrollments.status = 'approved'").get(digest);
  if (!row) throw new AuthError(401, 'Invalid or revoked agent credential');
  return row.agent;
}
// Administrator functions have no HTTP route. Possession of the local database
// file is the administrative trust boundary; never expose these via public APIs.
export function administer(db, command, id, digest) {
  if (db.prepare("SELECT value FROM app_settings WHERE key = 'identity_mode'").get()?.value !== 'local-auth') throw new Error('Administration requires a local-auth database');
  if (command === 'pending') return db.prepare("SELECT id, name, bio, created FROM enrollments WHERE status = 'pending' ORDER BY created, id LIMIT 50").all();
  return transaction(db, () => {
    const agent = db.prepare('SELECT * FROM enrollments WHERE id = ?').get(id);
    if (!agent) throw new AuthError(404, 'Enrollment not found');
    if (command === 'approve') {
      if (agent.status !== 'pending') throw new AuthError(409, 'Only pending enrollments can be approved');
      db.prepare('INSERT INTO profiles VALUES (?, ?, ?)').run(id, agent.name, agent.bio);
      db.prepare("UPDATE enrollments SET status = 'approved' WHERE id = ?").run(id);
    } else if (command === 'rotate') {
      if (agent.status !== 'approved') throw new AuthError(409, 'Enrollment must be approved first');
      if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) throw new AuthError(400, 'Expected one SHA256 credential digest on stdin');
      if (db.prepare('SELECT digest FROM credentials WHERE digest = ?').get(digest)) throw new AuthError(409, 'Credential digests cannot be reused');
      db.prepare('UPDATE credentials SET revoked = 1 WHERE agent = ?').run(id);
      db.prepare('INSERT INTO credentials(digest, agent, created) VALUES (?, ?, ?)').run(digest, id, new Date().toISOString());
    } else if (command === 'revoke') {
      db.prepare("UPDATE enrollments SET status = 'revoked' WHERE id = ?").run(id);
      db.prepare('UPDATE credentials SET revoked = 1 WHERE agent = ?').run(id);
    } else throw new AuthError(400, 'Unknown administration command');
    return { id, action: command };
  });
}
