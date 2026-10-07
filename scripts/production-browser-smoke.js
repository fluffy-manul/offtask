// Real Chromium + Rust + PostgreSQL public-viewer regression test. Synthetic only.
// Usage: scripts/with-test-postgres.sh node scripts/production-browser-smoke.js
// Requires built target/debug binaries, Node 24+, Chromium, TEST_DATABASE_URL.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { randomUUID } from 'node:crypto';

if (!process.env.TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL must identify a disposable synthetic PostgreSQL database.');
const root = resolve(import.meta.dirname, '..');
const freePort = createServer();
await new Promise(resolve => freePort.listen(0, '127.0.0.1', resolve));
const port = freePort.address().port;
await new Promise(resolve => freePort.close(resolve));
const base = `http://127.0.0.1:${port}`;
const env = { ...process.env, DATABASE_URL: process.env.TEST_DATABASE_URL, OFFTASK_MODE: 'production',
  NODE_ENV: 'test', OFFTASK_DATABASE_INSECURE: 'true', PUBLIC_ORIGIN: `https://127.0.0.1:${port}`, PORT: String(port) };
delete env.DATABASE_CA_CERT;
delete env.DATABASE_CA_CERT_PEM;
const run = randomUUID();
const directory = mkdtempSync(join(tmpdir(), 'offtask-production-browser-'));
const app = spawn(join(root, 'target/debug/offtask'), ['--production'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
let appLogs = '', browser, ws;
app.stdout.on('data', chunk => { appLogs += chunk; });
app.stderr.on('data', chunk => { appLogs += chunk; });
let appError;
app.on('error', error => { appError = error; });
const accounts = [];
const calls = new Map();
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function admin(...args) {
  return JSON.parse(execFileSync(join(root, 'target/debug/offtask-admin'), args, { env, encoding: 'utf8', timeout: 15000 }));
}
async function request(path, { method = 'GET', body, token, expected = 200 } = {}) {
  const response = await fetch(base + path, {
    method, headers: { ...(body ? { 'Content-Type': 'application/json', 'Idempotency-Key': randomUUID() } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(10000),
  });
  assert.equal(response.status, expected, `${method} ${path}: ${await response.clone().text()}`);
  return response.json();
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), pause(3000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await new Promise(resolve => child.once('exit', resolve));
  }
}

try {
  let healthy = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (appError) throw appError;
    if (app.exitCode !== null) throw new Error(`Rust server exited: ${appLogs}`);
    try { await request('/healthz'); healthy = true; break; } catch { await pause(100); }
  }
  assert.equal(healthy, true, `Rust server did not start: ${appLogs}`);
  const xss = '<img src=x onerror="window.xss=true">';
  for (const name of [xss, 'Synthetic browser participant']) {
    const { invitation } = admin('invite', `browser-${run}-${accounts.length}`);
    accounts.push(await request('/api/v1/enroll', { method: 'POST', expected: 201,
      body: { invitation, name, bio: 'Disposable synthetic browser fixture.', i_am_a_dot: true, declaration_version: 1 } }));
  }
  const token = accounts[0].accessToken;
  const title = `${xss} Browser fixture`;
  const body = `${xss}\n${'unbroken'.repeat(90)}`;
  async function create(title, body, extra = {}) {
    return request('/api/v1/conversations', { method: 'POST', token, expected: 201,
      body: { title, body, visibility: 'public', ...extra } });
  }
  const publicConversation = await create(title, body);
  const publicId = publicConversation.conversation.id;
  for (let i = 1; i <= 21; i++) {
    await request(`/api/v1/conversations/${publicId}/entries`, { method: 'POST', token,
      body: { body: `Synthetic entry ${i}` }, expected: 201 });
  }
  const second = await create('Synthetic second conversation', 'The newer conversation stays visible.');
  for (let i = 0; i < 20; i++) await create(`Synthetic list pagination ${run} ${i}`, `Synthetic body ${i}`);
  const privateMarker = `PRIVATE-SYNTHETIC-${run}`;
  const privateConversation = await create(privateMarker, privateMarker,
    { visibility: 'private', participants: [accounts[1].account] });
  await request(`/api/v1/conversations/${privateConversation.conversation.id}`, { expected: 404 });
  let allPublic = [], cursor;
  do {
    const page = await request('/api/v1/conversations?limit=100' + (cursor ? `&after=${cursor}` : ''));
    allPublic.push(...page.items);
    cursor = page.nextAfter;
  } while (cursor);

  browser = spawn(process.env.CHROMIUM || 'chromium', ['--headless', '--no-sandbox', '--disable-gpu',
    '--remote-debugging-port=0', `--user-data-dir=${directory}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const websocketUrl = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(`Chromium startup timed out: ${output}`)), 10000);
    browser.once('error', error => { clearTimeout(timer); reject(error); });
    browser.once('exit', code => { clearTimeout(timer); reject(new Error(`Chromium exited (${code}): ${output}`)); });
    browser.stderr.on('data', chunk => {
      output += chunk;
      const match = output.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  ws = new WebSocket(websocketUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let sequence = 0;
  const browserRequests = [], exceptions = [];
  ws.onmessage = event => {
    const message = JSON.parse(event.data), pending = calls.get(message.id);
    if (pending) {
      clearTimeout(pending.timer); calls.delete(message.id);
      message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result);
    }
    if (message.method === 'Network.requestWillBeSent') browserRequests.push(message.params.request);
    if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails);
  };
  function command(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => { calls.delete(id); reject(new Error(`CDP timed out: ${method}`)); }, 10000);
      calls.set(id, { resolve, reject, timer }); ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
  const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  await command('Network.enable', {}, sessionId);
  await command('Runtime.enable', {}, sessionId);
  await command('Page.enable', {}, sessionId);
  await command('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.viewerFetches = [];
    window.realFetch = window.fetch;
    window.fetch = (...args) => { window.viewerFetches.push({ path: args[0], options: args[1] }); return window.realFetch(...args); };
  ` }, sessionId);
  async function evaluate(expression) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function until(expression) {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await evaluate(expression)) return;
      await pause(50);
    }
    throw new Error(`Browser condition timed out: ${expression}`);
  }
  const clickTitle = title => evaluate(`[...document.querySelectorAll('#conversations button')].find(button => button.textContent === ${JSON.stringify(title)}).click()`);
  await command('Page.navigate', { url: base }, sessionId);
  await until('document.querySelectorAll("#conversations button").length === 20');
  assert.equal(await evaluate('document.querySelectorAll("input,textarea,form,[contenteditable=true]").length'), 0);
  assert.equal(await evaluate('document.querySelectorAll("#login,#token,#post,#message,#enrollment").length'), 0);
  assert.equal(await evaluate('document.body.textContent.includes(' + JSON.stringify(privateMarker) + ')'), false);
  while (await evaluate('!document.getElementById("more").hidden')) {
    const before = await evaluate('document.querySelectorAll("#conversations button").length');
    // A second click while loading must not append the same page twice.
    await evaluate('document.getElementById("more").click(); document.getElementById("more").click()');
    await until(`document.querySelectorAll('#conversations button').length > ${before}`);
    await until('!document.getElementById("more").disabled');
  }
  assert.equal(await evaluate('document.querySelectorAll("#conversations button").length'), allPublic.length);
  await clickTitle(title);
  await until('document.querySelectorAll("#entries article").length === 20');
  assert.equal(await evaluate('document.getElementById("title").textContent'), title);
  assert.equal(await evaluate('document.querySelector("#entries article p:last-child").textContent'), body);
  assert.equal(await evaluate('document.querySelector("#entries article p:first-child").textContent'), `${xss} · @${accounts[0].account}`);
  assert.equal(await evaluate('document.querySelectorAll("#entries img,#title img,#conversations img").length'), 0);
  assert.equal(await evaluate('window.xss === true'), false);
  await evaluate('document.getElementById("entries-more").click(); document.getElementById("entries-more").click()');
  await until('document.querySelectorAll("#entries article").length === 22');
  assert.equal(await evaluate('document.getElementById("entries-more").hidden'), true);
  assert.equal(new Set(await evaluate('[...document.querySelectorAll("#entries article p:last-child")].map(p => p.textContent)')).size, 22);

  for (const width of [390, 320]) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: true }, sessionId);
    assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, `Horizontal overflow at ${width}px`);
  }
  if (process.env.SCREENSHOT_DIR) {
    mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
    const screenshot = await command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, sessionId);
    writeFileSync(join(process.env.SCREENSHOT_DIR, 'production-viewer-mobile.png'), Buffer.from(screenshot.data, 'base64'));
  }

  async function delayPublic() {
    await evaluate(`window.releaseResponse = null; window.fetch = async (...args) => {
      const response = await window.realFetch(...args);
      if (String(args[0]).includes(${JSON.stringify(`/conversations/${publicId}?`)}))
        await new Promise(resolve => { window.releaseResponse = resolve; });
      return response;
    };`);
    await clickTitle(title);
    await until('typeof window.releaseResponse === "function"');
  }
  await delayPublic();
  assert.equal(await evaluate('document.getElementById("title").textContent'), 'Loading…');
  await evaluate('document.getElementById("back").click(); window.releaseResponse(); window.fetch = window.realFetch');
  await pause(100);
  assert.equal(await evaluate('document.getElementById("context").hidden'), true);
  assert.equal(await evaluate('document.getElementById("entries").children.length'), 0);
  await delayPublic();
  await clickTitle(second.conversation.title);
  await until('document.getElementById("title").textContent === "Synthetic second conversation"');
  await evaluate('window.releaseResponse(); window.fetch = window.realFetch');
  await pause(100);
  assert.equal(await evaluate('document.getElementById("title").textContent'), second.conversation.title);
  assert.equal(await evaluate('document.getElementById("entries").children.length'), 1);
  await evaluate(`[...document.querySelectorAll('#conversations button')].find(button => button.textContent === ${JSON.stringify(title)}).click();
    [...document.querySelectorAll('#conversations button')].find(button => button.textContent === ${JSON.stringify(title)}).click();`);
  await until('document.querySelectorAll("#entries article").length === 20');
  await pause(100);
  assert.equal(await evaluate('document.getElementById("entries").children.length'), 20);

  // A retryable API error must be readable, then recover on the next navigation.
  await evaluate('window.fetch = async () => new Response("{}", { status: 429 })');
  await clickTitle(second.conversation.title);
  await until('document.getElementById("title").textContent.includes("Please wait a minute")');
  assert.equal(await evaluate('document.getElementById("entries").children.length'), 0);
  await evaluate('window.fetch = window.realFetch');
  await clickTitle(second.conversation.title);
  await until('document.getElementById("title").textContent === "Synthetic second conversation"');
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  assert.equal(await evaluate('document.cookie'), '');
  assert.equal(await evaluate('window.viewerFetches.every(call => call.options.credentials === "omit" && call.options.cache === "no-store")'), true);
  const apiRequests = browserRequests.filter(item => item.url.startsWith(base + '/api/'));
  assert.ok(apiRequests.length > 0);
  assert.ok(apiRequests.every(item => item.method === 'GET' && !Object.keys(item.headers).some(key => /^(authorization|cookie)$/i.test(key))));
  assert.equal(JSON.stringify(browserRequests).includes(privateMarker), false);
  for (const account of accounts) {
    assert.equal(JSON.stringify(browserRequests).includes(account.accessToken), false);
    assert.equal(JSON.stringify(browserRequests).includes(account.recoveryToken), false);
  }
  assert.deepEqual(exceptions, []);
  console.log('Production Chromium smoke passed: actual PostgreSQL public viewer, no login/write controls or secret storage, private exclusion, safe title/body/profile rendering, listing/entry pagination, repeated clicks, 320px/390px layout, Back/newer-navigation races, and retryable-error recovery.');
} catch (error) {
  console.error(appLogs);
  throw error;
} finally {
  for (const call of calls.values()) clearTimeout(call.timer);
  ws?.close();
  await stop(browser);
  for (const account of accounts) {
    try { admin('revoke', account.account); } catch { /* The disposable database is removed by its caller. */ }
  }
  await stop(app);
  rmSync(directory, { recursive: true, force: true });
}
