// Real Chromium + Rust + PostgreSQL OAuth regression. All identities are synthetic.
// Usage: scripts/with-test-postgres.sh node scripts/oauth-browser-smoke.js
// Requires built target/debug binaries, Node 24+, Chromium, TEST_DATABASE_URL.
// CDP fulfills HTTPS requests from loopback HTTP without changing browser origins,
// cookies, form handling, or CSP. Nothing is forwarded to a public destination.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

if (!process.env.TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL must identify a disposable synthetic PostgreSQL database.');
const root = resolve(import.meta.dirname, '..');
const origin = 'https://offtask.example';
const callback = 'https://client.example/callback';
const client = 'synthetic-browser-client';
const resource = `${origin}/mcp`;
const verifier = 'synthetic-browser-verifier-' + randomUUID();
const challenge = createHash('sha256').update(verifier).digest('base64url');
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const directory = mkdtempSync(join(tmpdir(), 'offtask-oauth-browser-'));
// Even Chromium background traffic is confined to a local rejecting proxy.
const proxy = createServer((request, response) => { response.writeHead(502); response.end(); });
proxy.on('connect', (request, socket) => socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'));
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(server.address().port); });
});
let app, browser, ws, account, appError, routeError;
let appLogs = '', sequence = 0;
const calls = new Map(), routing = new Set();
const requests = [], callbacks = [], responses = [], exceptions = [], blocked = [];
const tickets = [], browserSecrets = [], oauthCodes = [], issuedTokens = [];
let env, base;
function admin(...args) {
  return JSON.parse(execFileSync(join(root, 'target/debug/offtask-admin'), args, { env, encoding: 'utf8', timeout: 30000 }));
}
// Node fetch normalizes Host to its URL authority. Use HTTP directly so Rust
// receives the browser's public authority while the socket stays on loopback.
function backend(path, { method = 'GET', headers = {}, body, timeout = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ hostname: '127.0.0.1', port: new URL(base).port, path, method,
      headers: { ...headers, Host: new URL(origin).host }, signal: AbortSignal.timeout(timeout) }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => {
        const headers = new Headers();
        for (let i = 0; i < response.rawHeaders.length; i += 2) headers.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
        resolve(new Response([204, 304].includes(response.statusCode) ? null : Buffer.concat(chunks), {
          status: response.statusCode, headers,
        }));
      });
    });
    request.on('error', reject);
    request.end(body === undefined ? undefined : String(body));
  });
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
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { calls.delete(id); reject(new Error(`CDP timed out: ${method}`)); }, 30000);
    calls.set(id, { resolve, reject, timer });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
const header = (headers, name) => Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
async function intercept(params, sessionId) {
  const { requestId, request } = params;
  requests.push(request);
  const url = new URL(request.url);
  if (url.origin === origin) {
    // Preserve browser-supplied Origin, Referer and Cookie exactly. Only transport
    // headers are adapted to the loopback HTTP connection; redirects stay in Chromium.
    const headers = Object.fromEntries(Object.entries(request.headers).filter(([key]) =>
      !['host', 'connection', 'content-length', 'accept-encoding'].includes(key.toLowerCase())));
    const response = await backend(url.pathname + url.search, {
      method: request.method, headers,
      ...(request.postData !== undefined ? { body: request.postData } : {}),
    });
    responses.push({ url: request.url, method: request.method, status: response.status, headers: Object.fromEntries(response.headers) });
    const responseHeaders = [...response.headers].filter(([name]) =>
      !['set-cookie', 'content-length', 'content-encoding', 'transfer-encoding', 'connection'].includes(name))
      .map(([name, value]) => ({ name, value }));
    for (const value of response.headers.getSetCookie()) responseHeaders.push({ name: 'set-cookie', value });
    await command('Fetch.fulfillRequest', { requestId, responseCode: response.status, responseHeaders,
      body: Buffer.from(await response.arrayBuffer()).toString('base64') }, sessionId);
  } else if (url.origin === new URL(callback).origin && url.pathname === new URL(callback).pathname) {
    callbacks.push(request);
    await command('Fetch.fulfillRequest', { requestId, responseCode: 200, responseHeaders: [
      { name: 'content-type', value: 'text/html; charset=utf-8' },
      { name: 'cache-control', value: 'no-store' },
      { name: 'referrer-policy', value: 'no-referrer' },
      { name: 'content-security-policy', value: "default-src 'none'; img-src data:; frame-ancestors 'none'" },
    ], body: Buffer.from('<!doctype html><title>Synthetic OAuth client</title><link rel="icon" href="data:,"><h1 id="callback">Synthetic callback received</h1>').toString('base64') }, sessionId);
  } else {
    blocked.push(`${request.method} ${url.origin}${url.pathname}`);
    await command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }, sessionId);
    throw new Error(`Unexpected browser destination: ${url.origin}${url.pathname}`);
  }
}

try {
  const proxyPort = await listen(proxy);
  const reservation = createServer();
  const port = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  base = `http://127.0.0.1:${port}`;
  // Never inherit real integration configuration, proxy credentials, or database CAs.
  env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(OFFTASK_|DATABASE_)/.test(key) && !/proxy/i.test(key)));
  Object.assign(env, { DATABASE_URL: process.env.TEST_DATABASE_URL, OFFTASK_MODE: 'production',
    NODE_ENV: 'test', OFFTASK_DATABASE_INSECURE: 'true', PUBLIC_ORIGIN: origin, PORT: String(port),
    OFFTASK_OAUTH_ENABLED: 'true', OFFTASK_OAUTH_CLIENT_ID: client, OFFTASK_OAUTH_REDIRECT_URIS: callback });
  app = spawn(join(root, 'target/debug/offtask'), ['--production'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  app.stdout.on('data', chunk => { appLogs += chunk; });
  app.stderr.on('data', chunk => { appLogs += chunk; });
  app.on('error', error => { appError = error; });
  let healthy = false;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (appError) throw appError;
    if (app.exitCode !== null) throw new Error(`Rust server exited: ${appLogs}`);
    try {
      const response = await backend('/healthz', { timeout: 1000 });
      if (response.ok) { healthy = true; break; }
    } catch { /* Wait for the local server. */ }
    await pause(100);
  }
  assert.ok(healthy, `Rust server did not start: ${appLogs}`);
  const { invitation } = admin('invite', `oauth-browser-${randomUUID()}`);
  const name = '<img src=x onerror="window.xss=true"> Synthetic dot-box';
  const enrolled = await backend('/api/v1/enroll', { method: 'POST', headers: {
    'Content-Type': 'application/json', 'Idempotency-Key': randomUUID(),
  }, body: JSON.stringify({ invitation, name, bio: 'Disposable OAuth browser fixture.', i_am_a_dot: true, declaration_version: 1 }) });
  assert.equal(enrolled.status, 201, `Synthetic enrollment failed: ${await enrolled.clone().text()}`);
  account = await enrolled.json();

  browser = spawn(process.env.CHROMIUM || 'chromium', ['--headless', '--no-sandbox', '--disable-gpu',
    '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions',
    '--disable-default-apps', '--no-first-run', '--no-default-browser-check', '--disable-quic',
    '--host-resolver-rules=MAP * ~NOTFOUND', `--proxy-server=http://127.0.0.1:${proxyPort}`,
    '--proxy-bypass-list=<-loopback>', '--remote-debugging-port=0', `--user-data-dir=${directory}`, 'about:blank'],
  { env, stdio: ['ignore', 'ignore', 'pipe'] });
  const websocketUrl = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(`Chromium startup timed out: ${output}`)), 30000);
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
  ws.onmessage = event => {
    const message = JSON.parse(event.data), pending = calls.get(message.id);
    if (pending) {
      clearTimeout(pending.timer); calls.delete(message.id);
      message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails);
    if (message.method === 'Fetch.requestPaused') {
      const work = intercept(message.params, message.sessionId).catch(error => { routeError ||= error; });
      routing.add(work);
      work.finally(() => routing.delete(work));
    }
  };
  const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const method of ['Network.enable', 'Runtime.enable', 'Page.enable']) await command(method, {}, sessionId);
  await command('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, sessionId);
  await command('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.cspViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.cspViolations.push({
      directive: event.effectiveDirective, blockedURI: event.blockedURI
    }));
  ` }, sessionId);
  async function evaluate(expression) {
    if (routeError) throw routeError;
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function until(expression) {
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      try { if (await evaluate(expression)) return; } catch (error) {
        // A real form navigation can replace the execution context between polls.
        if (!/Execution context was destroyed|Cannot find context|Inspected target navigated/i.test(error.message)) throw error;
      }
      await pause(50);
    }
    throw new Error(`Browser condition timed out: ${expression}`);
  }
  async function startFlow(label) {
    const state = `synthetic-${label}-${randomUUID()}`;
    const query = new URLSearchParams({ response_type: 'code', client_id: client, redirect_uri: callback,
      scope: 'offtask:read offtask:ack offtask:events', state, resource,
      code_challenge: challenge, code_challenge_method: 'S256' });
    await command('Page.navigate', { url: `${origin}/oauth/authorize?${query}` }, sessionId);
    await until(`location.origin === ${JSON.stringify(origin)} && document.querySelector('input[name="ticket"]') !== null`);
    assert.equal(await evaluate('window.isSecureContext'), true);
    assert.equal(await evaluate('document.cookie'), '');
    assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
    const { cookies } = await command('Network.getCookies', { urls: [origin] }, sessionId);
    const cookie = cookies.find(cookie => cookie.name === '__Host-offtask_oauth');
    assert.ok(cookie, 'Chromium must accept the real OAuth Set-Cookie header');
    assert.equal(cookie.secure, true); assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'Lax'); assert.equal(cookie.path, '/'); assert.equal(cookie.domain, 'offtask.example');
    browserSecrets.push(cookie.value);
    const { linkTicket } = admin('oauth-link', account.account);
    tickets.push(linkTicket);
    await evaluate(`document.querySelector('input[name="ticket"]').value = ${JSON.stringify(linkTicket)}`);
    return state;
  }
  async function missingCsrf(path) {
    const before = callbacks.length;
    const status = await evaluate(`(async () => {
      const body = new URLSearchParams(new FormData(document.querySelector('form')));
      body.delete('csrf');
      ${path === '/oauth/consent' ? "body.set('decision', 'approve');" : ''}
      return (await fetch(${JSON.stringify(path)}, { method: 'POST', body, redirect: 'error' })).status;
    })()`);
    assert.equal(status, 400, `Missing CSRF must fail on ${path}`);
    assert.equal(callbacks.length, before, 'A rejected CSRF request must not reach the callback');
  }
  async function review() {
    await evaluate('document.querySelector("button[type=submit]").click()');
    await until('document.querySelector("form[action=\"/oauth/consent\"]") !== null');
    assert.equal(await evaluate('document.querySelector("strong").textContent'), name);
    assert.equal(await evaluate('document.querySelectorAll("img").length'), 0);
    assert.equal(await evaluate('window.xss === true'), false);
    const text = await evaluate('document.body.textContent');
    for (const value of [account.account, client, resource, 'Acknowledge', 'notifications']) assert.ok(text.includes(value));
    for (const secret of tickets) assert.equal(await evaluate(`document.documentElement.outerHTML.includes(${JSON.stringify(secret)})`), false);
  }
  async function submit(decision) {
    await evaluate(`document.querySelector('button[value="${decision}"]').click()`);
    await until(`location.origin === ${JSON.stringify(new URL(callback).origin)} && document.getElementById('callback') !== null`);
    const result = new URL(await evaluate('location.href'));
    assert.equal(result.origin + result.pathname, callback);
    assert.equal(result.searchParams.get('iss'), origin);
    assert.equal(result.searchParams.get('resource'), resource);
    assert.equal(await evaluate('document.cookie'), '');
    assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
    return result.searchParams;
  }

  const approvedState = await startFlow('approve');
  await missingCsrf('/oauth/authorize');
  await review();
  assert.equal(callbacks.length, 0, 'Selecting a box must not grant access before consent');
  await missingCsrf('/oauth/consent');
  const consentFields = await evaluate('Object.fromEntries(new FormData(document.querySelector("form")))');
  // The OAuth CSP exception must not allow forms to arbitrary destinations.
  await evaluate(`document.querySelector('form').action = 'https://unregistered.example/callback'; document.querySelector('button[value="approve"]').click()`);
  await until('window.cspViolations.some(event => event.directive === "form-action")');
  assert.equal(callbacks.length, 0);
  assert.deepEqual(blocked, [], 'CSP must stop the unregistered form before the network layer');
  await evaluate('document.querySelector("form").action = "/oauth/consent"');
  const approved = await submit('approve');
  assert.equal(approved.get('state'), approvedState);
  assert.equal(approved.has('error'), false);
  assert.match(approved.get('code'), /^ot_code_/);
  assert.deepEqual([...approved.keys()].sort(), ['code', 'iss', 'resource', 'state']);
  oauthCodes.push(approved.get('code'));
  assert.equal(callbacks.length, 1, 'The registered cross-origin 303 must pass Chromium form-action');
  const remainingCookies = await command('Network.getCookies', { urls: [origin] }, sessionId);
  assert.equal(remainingCookies.cookies.some(cookie => cookie.name === '__Host-offtask_oauth'), false);

  const exchangeBody = new URLSearchParams({ grant_type: 'authorization_code', client_id: client,
    resource, code: approved.get('code'), redirect_uri: callback, code_verifier: verifier });
  async function exchange() {
    return backend('/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: exchangeBody });
  }
  const exchanged = await exchange();
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json();
  assert.match(tokens.access_token, /^ot_access_/); assert.match(tokens.refresh_token, /^ot_refresh_/);
  issuedTokens.push(tokens.access_token, tokens.refresh_token);
  assert.equal((await exchange()).status, 400, 'An authorization code is single-use');

  // Replay the consumed consent with an actual browser form. No new grant or
  // callback may result, including after navigating away and revisiting the origin.
  await command('Page.navigate', { url: `${origin}/healthz` }, sessionId);
  await until(`location.href === ${JSON.stringify(`${origin}/healthz`)} && document.readyState === 'complete'`);
  await evaluate(`{
    const form = document.createElement('form'); form.method = 'POST'; form.action = '/oauth/consent';
    for (const [name, value] of Object.entries(${JSON.stringify({ ...consentFields, decision: 'approve' })})) {
      const input = document.createElement('input'); input.name = name; input.value = value; form.append(input);
    }
    const button = document.createElement('button'); button.type = 'submit'; form.append(button);
    document.body.append(form); button.click();
  }`);
  await until('location.pathname === "/oauth/consent" && document.body.textContent.includes("invalid_request")');
  assert.equal(responses.filter(item => item.method === 'POST' && item.url === `${origin}/oauth/consent`).at(-1).status, 400);
  assert.equal(callbacks.length, 1, 'Consumed consent replay must not create another callback');
  const history = await command('Page.getNavigationHistory', {}, sessionId);
  const previous = history.entries[history.currentIndex - 1];
  assert.equal(previous.url, `${origin}/healthz`);
  await command('Page.navigateToHistoryEntry', { entryId: previous.id }, sessionId);
  await until(`location.href === ${JSON.stringify(`${origin}/healthz`)} && document.readyState === 'complete'`);
  assert.equal(callbacks.length, 1, 'Going Back after a rejected replay must not grant access');

  const deniedState = await startFlow('deny');
  await review();
  const denied = await submit('deny');
  assert.equal(denied.get('state'), deniedState);
  assert.equal(denied.get('error'), 'access_denied');
  assert.equal(denied.has('code'), false);
  assert.deepEqual([...denied.keys()].sort(), ['error', 'iss', 'resource', 'state']);
  assert.equal(callbacks.length, 2);

  await Promise.all([...routing]);
  if (routeError) throw routeError;
  assert.deepEqual(blocked, []);
  assert.deepEqual(exceptions, []);
  for (const request of callbacks) {
    assert.equal(request.method, 'GET');
    assert.equal(request.postData, undefined);
    for (const name of ['authorization', 'cookie', 'referer']) assert.equal(header(request.headers, name), undefined, `Callback must not receive ${name}`);
  }
  for (const request of requests) {
    const url = new URL(request.url);
    const serialized = JSON.stringify(request);
    for (const secret of [account.accessToken, account.recoveryToken, verifier, ...issuedTokens]) assert.equal(serialized.includes(secret), false, 'Long-lived keys and PKCE verifier must never enter browser requests');
    for (const secret of tickets) {
      if (serialized.includes(secret)) {
        assert.equal(request.url, `${origin}/oauth/authorize`); assert.equal(request.method, 'POST');
        assert.equal(request.url.includes(secret), false);
        assert.equal(JSON.stringify(request.headers).includes(secret), false, 'A link ticket belongs only in the selection POST body');
        assert.equal(header(request.headers, 'origin'), origin);
      }
    }
    for (const secret of browserSecrets) if (serialized.includes(secret)) assert.equal(url.origin, origin, 'Browser binding cookie must not leave its origin');
    for (const code of oauthCodes) if (serialized.includes(code)) assert.equal(url.origin + url.pathname, callback, 'Authorization code must only reach the registered callback');
  }
  for (const secret of [account.accessToken, account.recoveryToken, consentFields.request, consentFields.csrf, ...tickets, ...browserSecrets, ...oauthCodes, ...issuedTokens]) assert.equal(appLogs.includes(secret), false, 'Server logs must not contain credentials');
  const consentResponses = responses.filter(item => item.url === `${origin}/oauth/consent` && item.status === 303);
  assert.equal(consentResponses.length, 2);
  for (const response of consentResponses) {
    assert.ok(response.headers['content-security-policy'].includes("form-action 'self' https://client.example"));
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  console.log('OAuth Chromium smoke passed: synthetic HTTPS origins, Secure/HttpOnly cookies, real two-step consent, escaped box identity, CSRF rejection, registered cross-origin CSP redirect, unregistered form blocking, one-time code exchange, consumed-consent replay and Back, deny, and no credential leakage.');
} catch (error) {
  console.error(appLogs);
  throw error;
} finally {
  await stop(browser);
  await Promise.allSettled([...routing]);
  for (const call of calls.values()) clearTimeout(call.timer);
  ws?.close();
  if (account) { try { admin('revoke', account.account); } catch { /* Caller removes the disposable database. */ } }
  await stop(app);
  proxy.closeAllConnections();
  await new Promise(resolve => proxy.close(resolve));
  rmSync(directory, { recursive: true, force: true });
}
