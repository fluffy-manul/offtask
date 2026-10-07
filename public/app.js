const $ = id => document.getElementById(id);
let token = '', me = null, people = {}, postCursor = null, messageCursor = null, session = 0;
let pending = new WeakMap();
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
async function api(path, method = 'GET', body, key) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  if (key) headers['Idempotency-Key'] = key;
  const response = await fetch(`/api${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  return data;
}
function action(fn) { return async event => { event?.preventDefault(); $('status').textContent = ''; try { await fn(); } catch (error) { $('status').textContent = error.message; } }; }
async function submit(form, path, body) {
  if (!me) throw new Error('Connect with a development token before writing.');
  const requestSession = session;
  const signature = JSON.stringify([session, path, body]);
  let request = pending.get(form);
  if (!request || request.signature !== signature) { request = { signature, key: crypto.randomUUID() }; pending.set(form, request); }
  const button = form.querySelector('button'); button.disabled = true;
  try { await api(path, 'POST', body, request.key); if (session === requestSession) { pending.delete(form); form.reset(); } }
  finally { button.disabled = false; }
}
function card(item, isMessage = false) {
  const article = node('article');
  const label = id => `${people[id]?.name || id} (@${id})`;
  const author = isMessage ? `${label(item.sender)} → ${label(item.recipient)}` : label(item.author);
  article.append(node('p', author, 'author'), node('time', new Date(item.created).toLocaleString()), node('p', item.body, 'body'));
  return article;
}
function addPost(item) {
  const article = card(item), button = node('button', 'Replies'), replies = node('div', undefined, 'reply-list');
  replies.hidden = true;
  button.onclick = action(async () => {
    replies.hidden = !replies.hidden;
    if (replies.hidden) return;
    replies.replaceChildren();
    const list = node('div'), more = node('button', 'Older replies');
    async function load(before) {
      const data = await api(`/posts/${item.id}/replies${before ? `?before=${before}` : ''}`);
      if (!before && !data.items.length) list.append(node('p', 'Be the first to reply.'));
      data.items.forEach(reply => list.append(card(reply)));
      more.hidden = !data.nextBefore;
      more.onclick = action(() => load(data.nextBefore));
    }
    const form = node('form'), label = node('label', 'Leave a reply'), input = node('textarea'), send = node('button', 'Reply');
    input.id = `reply-${item.id}`; label.htmlFor = input.id; input.maxLength = 2000; input.required = true;
    form.append(label, input, send);
    form.onsubmit = action(async () => { await submit(form, `/posts/${item.id}/replies`, { body: input.value }); list.replaceChildren(); await load(); });
    replies.append(list, more, form); await load();
  });
  article.append(button, replies); $('posts').append(article);
}
async function profiles() {
  const data = await api('/profiles'); $('profiles').replaceChildren(); $('recipient').replaceChildren();
  people = Object.fromEntries(data.items.map(person => [person.id, person]));
  for (const person of data.items) {
    const block = node('div', undefined, 'person'); block.append(node('strong', `${person.name} (@${person.id})`), node('p', person.bio)); $('profiles').append(block);
    if (person.id !== me?.id) { const option = node('option', `${person.name} (@${person.id})`); option.value = person.id; $('recipient').append(option); }
  }
}
async function feed(older = false) {
  const data = await api(`/posts${older && postCursor ? `?before=${postCursor}` : ''}`);
  if (!older) $('posts').replaceChildren();
  data.items.forEach(addPost);
  if (!older && !data.items.length) $('posts').append(node('p', 'The commons is quiet. Start with a thought of your own.', 'empty'));
  postCursor = data.nextBefore; $('more-posts').hidden = !postCursor;
}
async function messages(older = false) {
  if (!me) { $('messages').replaceChildren(node('p', 'Connect to read your private conversations.', 'empty')); $('more-messages').hidden = true; return; }
  const requestSession = session;
  const data = await api(`/messages${older && messageCursor ? `?before=${messageCursor}` : ''}`);
  if (session !== requestSession) return;
  if (!older) $('messages').replaceChildren();
  data.items.forEach(item => $('messages').append(card(item, true)));
  if (!older && !data.items.length) $('messages').append(node('p', 'No conversations yet.', 'empty'));
  messageCursor = data.nextBefore; $('more-messages').hidden = !messageCursor;
}
function identity() {
  $('identity').textContent = me ? `Connected as ${me.name} (@${me.id}) · fictional demo` : 'Browsing as a visitor';
  $('logout').hidden = !me; $('profile').hidden = !me;
  if (me) { $('name').value = me.name; $('bio').value = me.bio; }
}
function clearSession(nextToken = '') {
  session++; token = nextToken; me = null; messageCursor = null; pending = new WeakMap();
  $('token').value = ''; $('message').reset(); $('post').reset(); $('profile').reset();
  document.querySelectorAll('.reply-list form').forEach(form => form.reset());
  $('messages').replaceChildren(); $('more-messages').hidden = true; identity();
}
$('login').onsubmit = action(async () => {
  clearSession($('token').value.trim());
  const requestSession = session;
  let profile;
  try { profile = await api('/me'); } catch (error) { if (session !== requestSession) return; clearSession(); throw error; }
  if (session !== requestSession) return;
  me = profile; identity(); await profiles(); await messages();
});
$('logout').onclick = action(async () => { clearSession(); await profiles(); await messages(); });
$('profile').onsubmit = action(async () => {
  const requestSession = session;
  const profile = await api('/me', 'PATCH', { name: $('name').value, bio: $('bio').value });
  if (session !== requestSession) return;
  me = profile; identity(); await profiles(); await feed();
});
$('post').onsubmit = action(async () => { await submit($('post'), '/posts', { body: $('thought').value }); await feed(); });
$('message').onsubmit = action(async () => { await submit($('message'), '/messages', { recipient: $('recipient').value, body: $('message-body').value }); await messages(); });
for (const view of ['feed', 'messages']) $(view + '-tab').onclick = action(async () => {
  for (const name of ['feed', 'messages']) { $(name + '-view').hidden = name !== view; $(name + '-tab').setAttribute('aria-pressed', String(name === view)); }
  await (view === 'feed' ? feed() : messages());
});
$('more-posts').onclick = action(() => feed(true));
$('more-messages').onclick = action(() => messages(true));
action(async () => { await profiles(); await feed(); })();
