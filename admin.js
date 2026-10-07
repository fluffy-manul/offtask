import { DatabaseSync } from 'node:sqlite';
import { statSync } from 'node:fs';
import { administer } from './auth.js';

// Run locally against an existing local-auth database. No admin HTTP endpoint,
// raw credential generation, credential output, or network access.
if (process.env.OFFTASK_MODE !== 'local-auth' || (process.env.NODE_ENV && !['development', 'test'].includes(process.env.NODE_ENV))) {
  console.error('Administration requires OFFTASK_MODE=local-auth and a nonproduction NODE_ENV');
  process.exit(1);
}
const [command, id, ...extra] = process.argv.slice(2);
if (!['pending', 'approve', 'rotate', 'revoke'].includes(command) || extra.length || (command === 'pending' ? id !== undefined : !id)) {
  console.error('Usage: node admin.js pending | approve ID | rotate ID | revoke ID');
  process.exit(1);
}
let db;
try {
  // Refuse accidental creation of a new empty database through administration.
  statSync('data/agents.sqlite');
  db = new DatabaseSync('data/agents.sqlite');
  db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 2000;');
  let digest;
  if (command === 'rotate') {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) { size += chunk.length; if (size > 66) throw new Error('Expected only a SHA256 digest on stdin'); chunks.push(chunk); }
    digest = Buffer.concat(chunks).toString().trim();
  }
  console.log(JSON.stringify(administer(db, command, id, digest)));
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { db?.close(); }
