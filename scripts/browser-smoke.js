// Optional real-browser smoke test. Uses installed Chromium, no npm dependency.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { createApp, credentialDigest } from './rust-fixture.js';
const tokens = { moss: 'm'.repeat(64), orbit: 'o'.repeat(64), lumen: 'l'.repeat(64) };
const app = createApp({ mode: 'development', nodeEnv: 'test', tokens });
await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${app.server.address().port}`;
const dir = mkdtempSync(join(tmpdir(), 'offtask-browser-'));
const browser = spawn(process.env.CHROMIUM || 'chromium', ['--headless', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0', `--user-data-dir=${dir}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let ws, enrollmentApp, previewApp;
try {
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Chromium startup timed out')), 10000);
    browser.once('error', error => { clearTimeout(timer); reject(error); });
    let output = '';
    browser.stderr.on('data', chunk => { output += chunk; const match = output.match(/DevTools listening on (ws:\/\/[^\s]+)/); if (match) { clearTimeout(timer); resolve(match[1]); } });
  });
  ws = new WebSocket(url);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let sequence = 0;
  const calls = new Map();
  ws.onmessage = event => {
    const message = JSON.parse(event.data), call = calls.get(message.id);
    if (call) { calls.delete(message.id); message.error ? call.reject(new Error(message.error.message)) : call.resolve(message.result); }
  };
  function command(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => { const id = ++sequence; calls.set(id, { resolve, reject }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
  }
  const { targetId } = await command('Target.createTarget', { url: base });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  async function evaluate(expression) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  }
  async function until(expression) {
    for (let i = 0; i < 100; i++) { if (await evaluate(expression)) return; await new Promise(resolve => setTimeout(resolve, 50)); }
    throw new Error(`Browser condition timed out: ${expression}`);
  }
  await until('document.querySelectorAll(".person").length === 3');
  await evaluate(`document.getElementById('token').value = '${tokens.moss}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('identity').textContent.includes('Connected as Moss')");
  const text = '<img src=x onerror="window.xss=true"> A fictional thought';
  await evaluate(`document.getElementById('thought').value = ${JSON.stringify(text)}; document.getElementById('post').requestSubmit()`);
  await until('document.querySelectorAll("#posts article").length === 1');
  assert.equal(await evaluate('document.querySelector("#posts .body").textContent'), text);
  assert.equal(await evaluate('document.querySelectorAll("#posts img").length'), 0);
  assert.equal(await evaluate('window.xss === true'), false);
  await evaluate("document.querySelector('#posts article button').click()");
  await until('document.querySelectorAll(".reply-list textarea").length === 1');
  await evaluate("document.querySelector('.reply-list textarea').value='A friendly reply'; document.querySelector('.reply-list form').requestSubmit()");
  await until("document.querySelector('.reply-list').textContent.includes('A friendly reply')");
  await evaluate("document.getElementById('messages-tab').click(); document.getElementById('recipient').value='orbit'; document.getElementById('message-body').value='A quiet hello'; document.getElementById('message').requestSubmit()");
  await until("document.getElementById('messages').textContent.includes('A quiet hello')");
  await evaluate("document.getElementById('logout').click()");
  await until("!document.getElementById('messages').textContent.includes('A quiet hello')");
  await evaluate(`document.getElementById('token').value = '${tokens.lumen}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('identity').textContent.includes('Connected as Lumen')");
  await until("document.getElementById('messages').textContent.includes('No conversations yet.')");
  // Delay one identity response, then connect as somebody else before it resolves.
  await evaluate(`window.realFetch = window.fetch; window.fetch = async (...args) => {
    const response = await window.realFetch(...args);
    if (args[0] === '/api/me' && args[1]?.headers?.Authorization === 'Bearer ${tokens.moss}') {
      await new Promise(resolve => { window.releaseLogin = resolve; });
    }
    return response;
  }; document.getElementById('token').value = '${tokens.moss}'; document.getElementById('login').requestSubmit()`);
  await until("typeof window.releaseLogin === 'function'");
  await evaluate(`document.getElementById('token').value = '${tokens.lumen}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('identity').textContent.includes('Connected as Lumen')");
  await evaluate("window.releaseLogin(); window.fetch = window.realFetch");
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.match(await evaluate("document.getElementById('identity').textContent"), /Connected as Lumen/);
  await evaluate("document.getElementById('message-body').value='Unsent private draft'; document.getElementById('logout').click()");
  assert.equal(await evaluate("document.getElementById('message-body').value"), '');
  // Editable display names never replace the stable profile ID shown to readers.
  await evaluate(`document.getElementById('token').value = '${tokens.moss}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('identity').textContent.includes('Connected as Moss')");
  await evaluate("document.getElementById('name').value='Orbit'; document.getElementById('bio').value='<img src=x onerror=alert(1)>'; document.getElementById('profile').requestSubmit()");
  await until("document.getElementById('profiles').textContent.includes('Orbit (@moss)')");
  assert.equal(await evaluate("document.querySelectorAll('#profiles img').length"), 0);
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, sessionId);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true);
  // Exercise the separate enrollment UI with synthetic identities only.
  enrollmentApp = createApp({ mode: 'local-auth', nodeEnv: 'test' });
  await new Promise(resolve => enrollmentApp.server.listen(0, '127.0.0.1', resolve));
  await command('Page.navigate', { url: `http://127.0.0.1:${enrollmentApp.server.address().port}` }, sessionId);
  await until("document.getElementById('mode-label')?.textContent === 'LOCAL AUTH PROTOTYPE'");
  assert.equal(await evaluate("document.querySelectorAll('.person').length"), 0);
  await evaluate("document.getElementById('enrollment-name').value='Synthetic browser agent'; document.getElementById('enrollment-bio').value='Synthetic test fixture'; document.getElementById('enrollment').requestSubmit()");
  await until("document.getElementById('enrollment-receipt').textContent.includes('Pending approval')");
  const agentId = await evaluate("document.getElementById('enrollment-receipt').textContent.match(/[0-9a-f-]{36}/)[0]");
  const syntheticToken = 'offtask_' + 'a'.repeat(64);
  await evaluate(`document.getElementById('token').value='${syntheticToken}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('status').textContent.includes('Invalid or revoked')");
  enrollmentApp.administer('approve', agentId);
  enrollmentApp.administer('rotate', agentId, credentialDigest(syntheticToken));
  await evaluate(`document.getElementById('token').value='${syntheticToken}'; document.getElementById('login').requestSubmit()`);
  await until("document.getElementById('identity').textContent.includes('Connected as Synthetic browser agent')");
  await until('document.querySelectorAll(".person").length === 1');
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true);
  enrollmentApp.administer('revoke', agentId);
  await evaluate("document.getElementById('thought').value='Revoked write'; document.getElementById('post').requestSubmit()");
  await until("document.getElementById('status').textContent.includes('Invalid or revoked')");
  previewApp = createApp({ mode: 'public-preview' });
  await new Promise(resolve => previewApp.server.listen(0, '127.0.0.1', resolve));
  await command('Page.navigate', { url: `http://127.0.0.1:${previewApp.server.address().port}` }, sessionId);
  await until("document.getElementById('mode-label')?.textContent === 'FICTIONAL PUBLIC PREVIEW'");
  await until('document.querySelectorAll("#posts > article").length === 2');
  for (const id of ['login-panel', 'post', 'messages-tab', 'enrollment-panel']) assert.equal(await evaluate(`document.getElementById('${id}').hidden`), true);
  await evaluate("document.querySelector('#posts article button').click()");
  await until('document.querySelector(".reply-list")?.hidden === false');
  assert.equal(await evaluate('document.querySelectorAll(".reply-list textarea").length'), 0);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true);
  console.log('Chromium smoke passed: login, post, safe text rendering, reply, DM, logout, nonparticipant view, login race, draft clearing, stable identity labels, profile XSS, mobile overflow, enrollment request, pending rejection, approval, revoked write rejection, read-only public preview.');
} finally {
  ws?.close(); browser.kill();
  await new Promise(resolve => { if (browser.exitCode !== null) resolve(); else browser.once('exit', resolve); });
  if (previewApp) await previewApp.close();
  if (enrollmentApp) await enrollmentApp.close();
  await app.close(); rmSync(dir, { recursive: true, force: true });
}
