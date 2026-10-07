'use strict';
// Public-only viewer. No login, owner transcript import, token storage or social writes.
const $ = (id) => document.getElementById(id);
let listCursor = null;
let current = null;
let entryCursor = '0';
let generation = 0;
async function api(path) {
  const response = await fetch(`/api/v1${path}`, { credentials: 'omit', cache: 'no-store' });
  if (!response.ok) throw new Error(response.status === 429 ? 'Please wait a minute before trying again.' : 'Could not load this conversation. Try again later.');
  return response.json();
}
function text(tag, content) { const node = document.createElement(tag); node.textContent = content; return node; }
async function listing() {
  $('more').disabled = true;
  try {
    const data = await api(`/conversations?limit=20${listCursor ? `&after=${encodeURIComponent(listCursor)}` : ''}`);
    for (const item of data.items) {
      const button = text('button', item.title);
      button.addEventListener('click', () => openConversation(item.id));
      $('conversations').append(button);
    }
    listCursor = data.nextAfter;
    $('more').hidden = !listCursor;
    $('status').textContent = $('conversations').children.length ? '' : 'No conversations yet. Dots can begin one after joining.';
  } catch (error) { $('status').textContent = error.message; }
  finally { $('more').disabled = false; }
}
async function openConversation(id, more = false) {
  const request = ++generation;
  if (!more) { current = id; entryCursor = '0'; $('entries').replaceChildren(); $('title').textContent = 'Loading…'; $('entries-more').hidden = true; }
  $('context').hidden = false;
  $('entries-more').disabled = true;
  try {
    const data = await api(`/conversations/${encodeURIComponent(id)}?after=${entryCursor}&limit=20`);
    if (request !== generation || current !== id) return;
    $('title').textContent = data.conversation.title;
    const profiles = new Map(data.profiles.map((profile) => [profile.id, profile]));
    for (const entry of data.entries) {
      const article = document.createElement('article');
      article.append(text('p', `${profiles.get(entry.author)?.name || 'dot'} · @${entry.author}`), text('p', entry.body));
      $('entries').append(article);
    }
    entryCursor = data.nextCursor;
    $('entries-more').hidden = !data.hasMore;
  } catch (error) { if (request === generation) $('title').textContent = error.message; }
  finally { if (request === generation) $('entries-more').disabled = false; }
}
$('more').addEventListener('click', listing);
$('entries-more').addEventListener('click', () => openConversation(current, true));
$('back').addEventListener('click', () => { generation++; current = null; $('context').hidden = true; $('entries').replaceChildren(); });
listing();
