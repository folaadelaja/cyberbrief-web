// Static Pages edition: personal browser storage, with portable export/import.
const PAGES_BOOKMARK_KEY = 'cyberbrief-pages-reading-v1';
async function bookmarkRequest(path, payload) {
  let list;
  try { list = JSON.parse(localStorage.getItem(PAGES_BOOKMARK_KEY) || '{}'); }
  catch { throw new Error('Saved data could not be read. Check browser storage settings.'); }
  if (!list || typeof list !== 'object' || Array.isArray(list)) throw new Error('Invalid saved data in browser storage.');
  const next = {...list};
  const candidates = () => [...data.items.filter(i => i.kind === 'news'), ...mergedCVEs(data.items)];
  function add(id) {
    const item = candidates().find(i => (i.cve ? 'cve:' + i.cve : i.id) === id);
    if (item) next[id] = item;
    return !!item;
  }
  const missing = [];
  if (payload) {
    if (path.endsWith('/import')) {
      for (const id of payload.ids) if (!add(id)) missing.push(id);
    } else if (payload.saved) {
      if (!next[payload.id] && !add(payload.id)) throw new Error('This article is no longer in the published feed.');
    } else delete next[payload.id];
    if (Object.keys(next).length > 1000) throw new Error('Reading list limit reached. Export your list before removing older entries.');
    try { localStorage.setItem(PAGES_BOOKMARK_KEY, JSON.stringify(next)); }
    catch { throw new Error('Browser storage is full or unavailable. Export your list and check storage settings.'); }
    list = next;
  }
  return {saved_ids:Object.keys(list), saved_items:Object.values(list), missing};
}
$('export-reading').addEventListener('click', async () => {
  try {
    const result = await bookmarkRequest('/api/bookmarks');
    const blob = new Blob([JSON.stringify({version:1, exported_at:new Date().toISOString(), saved_items:result.saved_items}, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = 'cyberbrief-reading-list.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { toast(error.message); }
});
$('import-reading').addEventListener('change', async event => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    if (file.size > 2_000_000) throw new Error('Choose a reading list smaller than 2 MB.');
    const result = JSON.parse(await file.text());
    if (result.version !== 1 || !Array.isArray(result.saved_items) || result.saved_items.length > 1000) throw new Error('Choose a CyberBrief reading-list export.');
    const existing = await bookmarkRequest('/api/bookmarks');
    const next = Object.fromEntries(existing.saved_items.map(i => [i.cve ? 'cve:' + i.cve : i.id, i]));
    const fields = ['id','source','sourceIds','kind','title','summary','url','published','first_seen','category','cve','score','exploited','kevAdded','action','due','vendor','product','ransomware'];
    for (const raw of result.saved_items) {
      if (!raw || !['news','cve'].includes(raw.kind) || typeof raw.id !== 'string' || raw.id.length > 200 || typeof raw.title !== 'string' || typeof raw.source !== 'string') throw new Error('The export contains an invalid article.');
      if (raw.kind === 'cve' && !/^CVE-\d{4}-\d{4,}$/.test(raw.cve)) throw new Error('The export contains an invalid CVE.');
      if (raw.score != null && (typeof raw.score !== 'number' || raw.score < 0 || raw.score > 10)) throw new Error('The export contains an invalid score.');
      if (typeof raw.url !== 'string' || !['https:','http:'].includes(new URL(raw.url).protocol)) throw new Error('The export contains an unsafe article URL.');
      if (raw.sourceIds && (!Array.isArray(raw.sourceIds) || raw.sourceIds.some(s => typeof s !== 'string'))) throw new Error('The export contains invalid sources.');
      const item = Object.fromEntries(fields.filter(k => Object.hasOwn(raw,k)).map(k => [k,raw[k]]));
      next[item.cve ? 'cve:' + item.cve : item.id] = item;
    }
    if (Object.keys(next).length > 1000) throw new Error('The combined list exceeds 1,000 saved articles.');
    localStorage.setItem(PAGES_BOOKMARK_KEY, JSON.stringify(next));
    await syncBookmarks(); toast('Reading list imported into this browser.');
  } catch (error) { toast(error.message || 'Unable to import this reading list.'); }
  finally { event.target.value = ''; }
});
