'use strict';
const $ = id => document.getElementById(id);
const readLocal = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
const persist = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { toast('Your browser could not save this preference.'); } };
let view = 'briefing', topic = 'all', limit = 12, data = null, loading = false, statScope = null;
let saved = new Set(), savedItems = [], bookmarksReady = false, bookmarkBusy = false, bookmarkVersion = 0;
let disabled = new Set(readLocal('cyberbrief-disabled', []));
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeLink = value => { try { const u = new URL(value); return ['http:', 'https:'].includes(u.protocol) ? escapeHTML(u.href) : '#'; } catch { return '#'; } };
const timeLabel = value => { if (!value) return 'Date unavailable'; const seconds = Math.max(0, (Date.now() - new Date(value)) / 1000); if (seconds < 60) return 'Just now'; if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`; return new Date(value).toLocaleDateString(undefined, {month:'short', day:'numeric'}); };
const fullDate = value => value ? new Date(value).toLocaleString() : 'Not yet collected';
const recent = (item, days) => !!item.published && new Date(item.published) >= Date.now() - days * 86400000;
const initials = name => name.split(/\s+/).map(s => s[0]).join('').slice(0, 2).toUpperCase();
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => $('toast').hidden = true, 4500); }
function enabledItems() { const subscribed = new Set(data.sources.filter(s => !disabled.has(s.id)).map(s => s.id)); return data.items.filter(i => subscribed.has(i.source)); }
function mergedCVEs(items) {
  const map = new Map();
  for (const item of items.filter(i => i.kind === 'cve')) {
    const old = map.get(item.cve);
    if (!old) { map.set(item.cve, {...item, sourceIds:[item.source]}); continue; }
    const kev = item.exploited ? item : old;
    const nvd = item.source === 'nvd' ? item : old;
    map.set(item.cve, {...nvd, sourceIds:[...old.sourceIds,item.source], exploited:kev.exploited,
      title:kev.exploited ? kev.title : nvd.title, action:kev.action, due:kev.due, vendor:kev.vendor, product:kev.product,
      kevAdded:kev.exploited ? kev.published : null, ransomware:kev.ransomware,
      summary:nvd.summary || kev.summary});
  }
  return [...map.values()].map(i => ({...i, kevAdded:i.kevAdded || (i.exploited && i.source === 'cisa' ? i.published : null)})).sort((a,b) => String(b.kevAdded > b.published ? b.kevAdded : b.published || b.first_seen).localeCompare(String(a.kevAdded > a.published ? a.kevAdded : a.published || a.first_seen)));
}
function scoreTag(item) {
  if (item.score == null) return '<span class="tag">CVSS unscored</span>';
  const severity = item.score >= 9 ? 'Critical' : item.score >= 7 ? 'High' : item.score >= 4 ? 'Medium' : 'Low';
  return `<span class="tag ${item.score >= 9 ? 'red' : item.score >= 7 ? 'orange' : ''}">CVSS ${escapeHTML(item.score.toFixed(1))} · ${severity}</span>`;
}
function sourceName(id) { return data.sources.find(s => s.id === id)?.name || id; }
function storyCard(item, index) {
  const name = item.sourceIds ? item.sourceIds.map(sourceName).join(' + ') : sourceName(item.source);
  const saveId = item.cve ? 'cve:' + item.cve : item.id;
  const isSaved = saved.has(saveId);
  return `<article class="story ${index === 0 && view === 'briefing' ? 'featured' : ''}">
    <div class="story-top"><span class="source-logo" aria-hidden="true">${escapeHTML(initials(sourceName(item.source)))}</span><span class="source-name">${escapeHTML(name)}</span><span>·</span><time datetime="${escapeHTML(item.published || '')}" title="${escapeHTML(fullDate(item.published))}">${timeLabel(item.published)}</time></div>
    <button class="save-button ${isSaved ? 'saved' : ''}" data-save="${escapeHTML(saveId)}" ${!bookmarksReady || bookmarkBusy ? 'disabled' : ''} aria-label="${isSaved ? 'Unsave' : 'Save'} story" aria-pressed="${isSaved}" title="${isSaved ? 'Remove from saved' : 'Save for later'}">${isSaved ? '▰' : '▱'}</button>
    <h3><a href="${safeLink(item.url)}" target="_blank" rel="noopener noreferrer">${item.kind === 'cve' && item.title !== item.cve ? `${escapeHTML(item.cve)}: ` : ''}${escapeHTML(item.title)}</a></h3>
    <p>${escapeHTML(item.summary || 'Open the original source for full details.')}</p>
    <div class="story-bottom">${item.kind === 'cve' ? scoreTag(item) : `<span class="tag green">${escapeHTML(item.category)}</span>`}${item.exploited ? '<span class="tag red">Known exploited</span>' : ''}${item.kind === 'cve' ? `<button class="read-link" data-detail="${escapeHTML(item.cve)}">View details</button>` : `<a class="read-link" href="${safeLink(item.url)}" target="_blank" rel="noopener noreferrer">Read article</a>`}</div></article>`;
}
function filteredItems() {
  const enabled = enabledItems();
  let items = view === 'vulnerabilities' ? mergedCVEs(enabled) : view === 'saved' ? savedItems : enabled.filter(i => i.kind === 'news');
  const query = $('search').value.trim().toLowerCase(), source = $('source-filter').value, days = $('time-filter').value;
  return items.filter(i => {
    if (statScope === 'published' && !recent(i, 7)) return false;
    if (statScope === 'kev' && (!i.kevAdded || !recent({published:i.kevAdded}, 7))) return false;
    if (source !== 'all' && !(i.sourceIds || [i.source]).includes(source)) return false;
    if (days !== 'all' && !recent(i, Number(days)) && !(i.kevAdded && recent({published:i.kevAdded}, Number(days)))) return false;
    if (view === 'briefing' && topic !== 'all' && i.category !== topic) return false;
    if (query && ![i.title, i.summary, i.cve, i.vendor, i.product, sourceName(i.source)].join(' ').toLowerCase().includes(query)) return false;
    if (view === 'vulnerabilities') {
      if ($('exploited-only').checked && !i.exploited) return false;
      const severity = $('severity-filter').value;
      const s = i.score == null ? 'unscored' : i.score >= 9 ? 'critical' : i.score >= 7 ? 'high' : i.score >= 4 ? 'medium' : 'low';
      if (severity !== 'all' && severity !== s) return false;
    }
    return true;
  }).sort((a,b) => {
    const order = $('sort-order').value;
    if (order === 'severity' && view === 'vulnerabilities') {
      const scoreDifference = (b.score ?? -1) - (a.score ?? -1);
      if (scoreDifference) return scoreDifference;
    }
    const date = i => String(i.kevAdded > i.published ? i.kevAdded : i.published || i.first_seen || '');
    return order === 'oldest' ? date(a).localeCompare(date(b)) : date(b).localeCompare(date(a));
  });
}
function emptyState(title, text) { return `<div class="empty"><span aria-hidden="true">⌁</span><h3>${title}</h3><p>${text}</p></div>`; }
function renderItems() {
  if (!data) return;
  $('saved-count').textContent = saved.size;
  if (view === 'sources') { renderSources(); return; }
  const items = filteredItems();
  $('result-count').textContent = `${items.length.toLocaleString()} ${view === 'vulnerabilities' ? 'CVEs' : 'items'}`;
  $('items').className = view === 'vulnerabilities' ? 'cve-grid' : '';
  $('items').innerHTML = items.length ? items.slice(0, limit).map(storyCard).join('') : emptyState(view === 'saved' ? 'Make room for a deeper read.' : !data.items.length ? (data.refreshing ? 'Building your first briefing.' : 'Your feeds are quiet for now.') : 'No stories in this view.', view === 'saved' ? 'Save a story using its bookmark button. Your saved list syncs across devices using this dashboard.' : !data.items.length ? 'Live content will appear after the first successful collection. Check Sources & feeds for collection status.' : 'Try a longer time range, a different topic, or another search. Source subscriptions also affect this view.');
  $('load-more').hidden = items.length <= limit;
  $('load-more').textContent = `Load more ${view === 'vulnerabilities' ? 'CVEs' : 'stories'}`;
}
function renderSources() {
  $('items').className = '';
  $('result-count').textContent = `${data.sources.length} sources`;
  $('load-more').hidden = true;
  $('items').innerHTML = data.sources.map(s => `<article class="source-card"><div class="source-card-header"><span class="source-logo">${escapeHTML(initials(s.name))}</span><h3>${escapeHTML(s.name)}</h3><label class="toggle"><input type="checkbox" data-subscribe="${escapeHTML(s.id)}" ${disabled.has(s.id) ? '' : 'checked'}>Subscribed</label></div><p><a href="${safeLink(s.url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(s.url)} ↗</a></p><div class="source-meta"><span class="tag ${s.error ? 'orange' : s.last_success ? 'green' : ''}">${s.error ? 'Collection failed' : s.last_success ? 'Connected' : 'Awaiting first collection'}</span><span>Last success: ${escapeHTML(fullDate(s.last_success))}</span><span>Latest collection: ${s.count || 0} items</span></div>${s.error ? `<p class="source-error">${escapeHTML(s.error)}<br>Cached content is retained. The collector will retry automatically.</p>` : ''}</article>`).join('') + '<p class="subtitle source-help">Subscriptions personalize this browser. The server continues collecting all configured feeds. Saved articles are shared across devices.</p>';
}
function renderSidebar() {
  const enabled = enabledItems();
  const priority = enabled.filter(i => i.source === 'cisa').sort((a,b) => String(b.published).localeCompare(String(a.published))).slice(0, 3);
  $('priority-items').innerHTML = priority.length ? priority.map(i => `<div class="priority-item"><button data-detail="${escapeHTML(i.cve)}"><span class="cve-id">${escapeHTML(i.cve)} <span aria-hidden="true">↗</span></span><span class="cve-title">${escapeHTML(i.title)}</span><small>Added ${escapeHTML(timeLabel(i.published))}</small></button></div>`).join('') : '<p class="subtitle">CISA entries will appear here after collection. Check your source subscription and feed health.</p>';
  $('health-list').innerHTML = data.sources.filter(s => !disabled.has(s.id)).map(s => `<div class="health-row"><span><i class="${s.error ? 'error' : !s.last_success ? 'pending' : ''}"></i>${escapeHTML(s.name)}</span><small>${s.error ? 'Retry pending' : s.last_success ? timeLabel(s.last_success) : 'Pending'}</small></div>`).join('') || '<p class="subtitle">No sources subscribed</p>';
  const successes = data.sources.map(s => s.last_success).filter(Boolean).sort();
  $('last-check').textContent = successes.length ? `Last successful collection ${fullDate(successes.at(-1))}` : 'Waiting for first successful collection';
}
function render() {
  if (!data) return;
  const enabled = enabledItems(), sources = data.sources.filter(s => !disabled.has(s.id));
  $('stat-news').textContent = enabled.filter(i => i.kind === 'news' && recent(i, 1)).length.toLocaleString();
  $('stat-cves').textContent = mergedCVEs(enabled).filter(i => recent(i, 7)).length.toLocaleString();
  $('stat-kev').textContent = enabled.filter(i => i.source === 'cisa' && recent(i, 7)).length.toLocaleString();
  const healthy = sources.filter(s => s.last_success && !s.error).length;
  $('stat-sources').textContent = `${healthy} / ${sources.length}`;
  $('source-caption').textContent = `${sources.length} subscribed · ${sources.filter(s => s.error).length} need attention`;
  $('connection').textContent = data.refreshing ? 'Collecting feeds' : 'Collector online';
  $('refresh-icon').classList.toggle('spin', data.refreshing);
  $('refresh').disabled = data.refreshing;
  $('schedule').textContent = data.next_refresh ? `Next collection ${new Date(data.next_refresh).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})} · page checks every minute` : 'Collecting feeds · page checks every minute';
  const failed = sources.filter(s => s.error).length;
  const latest = Math.max(0, ...sources.map(s => s.last_success ? Date.parse(s.last_success) : 0));
  const stale = latest && Date.now() - latest > data.interval_seconds * 2000;
  $('notice').hidden = !failed && !stale;
  $('notice').textContent = stale ? 'Collection is overdue. Cached content is shown. Check the server and source status.' : `${failed} source${failed === 1 ? '' : 's'} could not be reached. Cached stories remain available; failed feeds will retry automatically. See Sources & feeds for details.`;
  renderSidebar(); renderItems();
}
function setView(next) {
  view = next; limit = 12; topic = 'all'; statScope = null;
  const config = {briefing:['Daily briefing','Your daily security briefing.','News, vulnerabilities, and observed threats. A clearer view of what matters.','Latest intelligence','Fresh reporting from your subscribed security sources.'], vulnerabilities:['Vulnerabilities','Know what needs attention.','Recent CVEs, CVSS scores, and confirmed exploitation.','Vulnerability watch','NVD disclosures and the CISA KEV catalog, brought together.'], saved:['Saved stories','Worth another look.','Your reading list, ready when you are.','Your reading list','Stories and CVEs saved to your shared reading list.'], sources:['Sources & feeds','Good intelligence starts here.','Trusted publishers. Official catalogs. Your own perspective.','Your sources','Control your subscriptions and see the health of every feed.']}[view];
  $('breadcrumb').textContent = config[0]; $('page-title').textContent = config[1]; $('page-subtitle').textContent = config[2]; $('section-title').textContent = config[3]; $('section-caption').textContent = config[4];
  document.querySelectorAll('[data-view]').forEach(b => { b.classList.toggle('active', b.dataset.view === view); b.setAttribute('aria-current', b.dataset.view === view ? 'page' : 'false'); });
  document.querySelectorAll('[data-category]').forEach(b => b.classList.toggle('active', b.dataset.category === 'all'));
  $('content-layout').classList.toggle('wide', view !== 'briefing'); $('right-column').hidden = view !== 'briefing';
  $('filters').hidden = view === 'sources'; $('categories').hidden = view !== 'briefing'; $('severity-filter').hidden = view !== 'vulnerabilities'; $('cve-options').hidden = view !== 'vulnerabilities';
  $('time-filter').value = view === 'saved' ? 'all' : '7'; $('source-filter').value = 'all'; $('search').value = ''; $('exploited-only').checked = false; $('severity-filter').value = 'all';
  $('sort-order').value = 'newest';
  $('sort-severity').hidden = view !== 'vulnerabilities';
  document.querySelector('.threat-radar').hidden = view !== 'briefing';
  if (typeof history !== 'undefined' && typeof location !== 'undefined') history.replaceState(null, '', '#' + view);
  renderItems();
}
function openStat(key) {
  if (key === 'sources') setView('sources');
  else if (key === 'news') { setView('briefing'); $('time-filter').value = '1'; }
  else if (key === 'cves') { setView('vulnerabilities'); $('time-filter').value = '7'; statScope = 'published'; }
  else if (key === 'kev') { setView('vulnerabilities'); $('time-filter').value = '7'; $('source-filter').value = 'cisa'; $('exploited-only').checked = true; statScope = 'kev'; }
  else return;
  renderItems();
  $('content-layout').scrollIntoView({behavior:typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block:'start'});
}
function detail(cve) {
  const item = mergedCVEs(enabledItems()).find(i => i.cve === cve);
  if (!item) return;
  $('detail-content').innerHTML = `<span class="tag green">${escapeHTML(item.cve)}</span> ${scoreTag(item)} ${item.exploited ? '<span class="tag red">Known exploited</span>' : ''}<h2>${escapeHTML(item.title)}</h2><p>${escapeHTML(item.summary)}</p>${item.action ? `<h4>CISA required action</h4><p>${escapeHTML(item.action)}</p><div class="dialog-meta">CISA due date: ${escapeHTML(item.due || 'Not specified')} (federal agency remediation deadline)<br>Added to KEV: ${escapeHTML(fullDate(item.kevAdded))}${item.ransomware ? '<br>CISA reports known ransomware campaign use.' : ''}</div>` : ''}<p class="dialog-meta">Published: ${escapeHTML(fullDate(item.published))}<br>Sources: ${escapeHTML((item.sourceIds || [item.source]).map(sourceName).join(', '))}${item.score == null ? '<br>No CVSS score available in collected data.' : ''}</p><a class="button" href="${safeLink(item.url)}" target="_blank" rel="noopener noreferrer">Open NVD record</a>`;
  $('detail').showModal();
}
function applyBookmarks(result) {
  saved = new Set(result.saved_ids);
  savedItems = result.saved_items;
  bookmarksReady = true;
}
async function bookmarkRequest(path, payload) {
  const response = await fetch(path, payload === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-CyberBrief':'bookmarks'}, body:JSON.stringify(payload)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Bookmark sync failed');
  return result;
}
async function syncBookmarks() {
  if (bookmarkBusy) return;
  const version = bookmarkVersion;
  try {
    const legacy = readLocal('cyberbrief-saved', []);
    let result;
    if (Array.isArray(legacy) && legacy.length) {
      bookmarkBusy = true;
      result = await bookmarkRequest('/api/bookmarks/import', {ids:legacy.slice(0, 1000)});
      // Clear only after the server acknowledges the import, so another device can remove a bookmark permanently.
      persist('cyberbrief-saved', legacy.slice(1000));
      if (result.missing?.length) toast('Some older bookmarks were no longer available in the collected feeds.');
    } else result = await bookmarkRequest('/api/bookmarks');
    if (version === bookmarkVersion) applyBookmarks(result);
    renderItems();
  } catch { toast('Bookmarks could not sync. Your existing saved list is unchanged.'); }
  finally { bookmarkBusy = false; renderItems(); }
}
async function toggleBookmark(id) {
  if (!bookmarksReady || bookmarkBusy) return;
  bookmarkBusy = true; bookmarkVersion++;
  renderItems();
  try {
    applyBookmarks(await bookmarkRequest('/api/bookmarks', {id, saved:!saved.has(id)}));
  } catch (error) { toast(error.message); }
  finally { bookmarkBusy = false; renderItems(); }
}
async function load() {
  if (loading) return; loading = true;
  try {
    const response = await fetch('/api/dashboard'); if (!response.ok) throw new Error(`HTTP ${response.status}`);
    data = await response.json();
    await syncBookmarks();
    if ($('source-filter').options.length === 1) data.sources.forEach(s => { const option = document.createElement('option'); option.value = s.id; option.textContent = s.name; $('source-filter').appendChild(option); });
    render();
  } catch {
    $('connection').textContent = 'Server unavailable'; $('notice').hidden = false; $('notice').textContent = 'The server could not be reached. Previously loaded content is still shown. Retrying automatically.';
    if (!data) $('items').innerHTML = emptyState('Unable to load your briefing.', 'Check that the CyberBrief server is running. This page will retry automatically.');
  } finally { loading = false; }
}
document.addEventListener('click', event => {
  const stat = event.target.closest('[data-stat]'); if (stat) openStat(stat.dataset.stat);
  const nav = event.target.closest('[data-view]'); if (nav) setView(nav.dataset.view);
  const cat = event.target.closest('[data-category]'); if (cat) { topic = cat.dataset.category; limit = 12; document.querySelectorAll('[data-category]').forEach(b => b.classList.toggle('active', b === cat)); renderItems(); }
  const save = event.target.closest('[data-save]'); if (save) toggleBookmark(save.dataset.save);
  const more = event.target.closest('[data-detail]'); if (more) detail(more.dataset.detail);
});
document.addEventListener('change', event => {
  if (event.target.matches('[data-subscribe]')) { const id = event.target.dataset.subscribe; event.target.checked ? disabled.delete(id) : disabled.add(id); persist('cyberbrief-disabled', [...disabled]); render(); }
});
['source-filter','time-filter','severity-filter','exploited-only'].forEach(id => $(id).addEventListener('change', () => { limit = 12; statScope = null; renderItems(); }));
$('sort-order').addEventListener('change', () => { limit = 12; renderItems(); });
$('reset-filters').addEventListener('click', () => setView(view));
$('search').addEventListener('input', () => { limit = 12; renderItems(); });
$('load-more').addEventListener('click', () => { limit += 12; renderItems(); });
$('manage-sources').addEventListener('click', () => setView('sources'));
$('view-kev').addEventListener('click', () => { setView('vulnerabilities'); $('exploited-only').checked = true; $('time-filter').value = 'all'; renderItems(); });
$('refresh').addEventListener('click', async () => {
  $('refresh').disabled = true;
  try { const response = await fetch('/api/refresh', {method:'POST', headers:{'X-CyberBrief':'refresh'}}); const result = await response.json(); toast(result.message || 'Unable to refresh feeds'); if (response.ok) { setTimeout(load, 1200); setTimeout(load, 8000); } }
  catch { toast('Unable to reach the collector.'); }
  finally { $('refresh').disabled = !!data?.refreshing; }
});
$('theme-toggle').addEventListener('click', () => { document.body.classList.toggle('dark'); persist('cyberbrief-dark', document.body.classList.contains('dark')); });
document.body.classList.toggle('dark', readLocal('cyberbrief-dark', true));
document.querySelector('.dialog-close').addEventListener('click', () => $('detail').close());
$('detail').addEventListener('click', e => { if (e.target === $('detail')) { const r = $('detail').getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) $('detail').close(); } });
document.addEventListener('keydown', e => { if (e.key === '/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName) && view !== 'sources' && !$('detail').open) { e.preventDefault(); $('search').focus(); } });
$('today').textContent = new Date().toLocaleDateString(undefined, {weekday:'long', month:'short', day:'numeric', year:'numeric'});
$('items').innerHTML = emptyState('Your briefing is on its way.', 'Connecting to the feed collector…');
if (typeof location !== 'undefined' && ['briefing','vulnerabilities','saved','sources'].includes(location.hash.slice(1))) setView(location.hash.slice(1));
if (typeof window !== 'undefined') window.addEventListener('hashchange', () => { const next = location.hash.slice(1); if (['briefing','vulnerabilities','saved','sources'].includes(next)) setView(next); });
load(); setInterval(load, 60000); setInterval(syncBookmarks, 15000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
