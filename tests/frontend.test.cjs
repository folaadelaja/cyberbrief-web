// Optional frontend logic checks: node tests/frontend.test.cjs
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {value:id === 'time-filter' ? '7' : ['source-filter','severity-filter'].includes(id) ? 'all' : '', textContent:'', innerHTML:'', hidden:false, checked:false, options:[{}], dataset:{}, classList:{toggle() {},contains() {return false;}}, addEventListener() {}, setAttribute() {}, appendChild(option) {this.options.push(option);}, showModal() {}, close() {}, focus() {}, scrollIntoView() {}, getAttribute() {return null;}});
  return elements.get(id);
}
const stamp = new Date().toISOString();
const fixture = {items:[
  {id:'news1', source:'news',kind:'news',title:'A phishing campaign',summary:'<img onerror=alert(1)>',published:stamp,category:'Threats',url:'https://example.com/news'},
  {id:'nvd:CVE-2026-12345',source:'nvd',kind:'cve',title:'CVE-2026-12345',summary:'A vulnerability',cve:'CVE-2026-12345',published:'2020-01-01T00:00:00Z',score:9.8,url:'https://nvd.nist.gov/vuln/detail/CVE-2026-12345'},
  {id:'kev:CVE-2026-12345',source:'cisa',kind:'cve',title:'Vendor vulnerability',summary:'Exploited',cve:'CVE-2026-12345',published:stamp,exploited:true,score:null,url:'https://nvd.nist.gov/vuln/detail/CVE-2026-12345'}
], sources:[{id:'news',name:'News',last_success:stamp},{id:'nvd',name:'NVD',last_success:stamp},{id:'cisa',name:'CISA',last_success:stamp}],refreshing:false,interval_seconds:3600};
const serverSaved = new Set();
const browserStorage = new Map([['cyberbrief-saved', JSON.stringify(['news1'])]]);
let failBookmarks = false;
const snapshot = () => ({saved_ids:[...serverSaved], saved_items:[...serverSaved].map(id => id.startsWith('cve:') ? {...fixture.items[1],title:fixture.items[2].title,exploited:true,kevAdded:stamp} : fixture.items.find(i => i.id === id)).filter(Boolean)});
async function mockFetch(url, options = {}) {
  if (url === '/api/dashboard') return {ok:true,json:async()=>fixture};
  if (failBookmarks) return {ok:false,json:async()=>({error:'Save failed'})};
  const body = options.body ? JSON.parse(options.body) : null;
  if (url.endsWith('/import')) body.ids.forEach(id => serverSaved.add(id));
  else if (body) body.saved ? serverSaved.add(body.id) : serverSaved.delete(body.id);
  return {ok:true,json:async()=>snapshot()};
}
const context = vm.createContext({console,URL,localStorage:{getItem(key){return browserStorage.get(key) || null;},setItem(key,value){browserStorage.set(key,value);}},document:{createElement:()=>({}),getElementById:element,querySelector:element,querySelectorAll:()=>[],addEventListener(){},body:element('body')},fetch:mockFetch,setTimeout(){},clearTimeout(){},setInterval(){}});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../static/app.js'),'utf8'),context);
module.exports = (async () => {
  await new Promise(resolve => setImmediate(resolve));
  assert(serverSaved.has('news1'), 'Legacy bookmarks import to the server');
  assert.equal(browserStorage.get('cyberbrief-saved'), '[]');
  assert.match(element('items').innerHTML, /phishing campaign/);
  assert.match(element('items').innerHTML, /&lt;img onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(element('items').innerHTML, /<img onerror/);
  vm.runInContext("setView('vulnerabilities')", context);
  assert.equal(vm.runInContext('filteredItems().length',context),1);
  assert.match(element('items').innerHTML,/CVSS 9.8 · Critical/);
  assert.match(element('items').innerHTML,/Known exploited/);
  // Recent KEV additions remain visible even if the CVE publication date is older.
  assert.match(element('items').innerHTML,/Vendor vulnerability/);
  await vm.runInContext("toggleBookmark('news1')",context);
  await vm.runInContext("toggleBookmark('cve:CVE-2026-12345')",context);
  vm.runInContext("setView('saved')",context);
  assert.equal(vm.runInContext('filteredItems().length',context),1);
  assert.match(element('items').innerHTML,/aria-pressed="true"/);
  vm.runInContext("disabled.add('cisa'); setView('vulnerabilities'); $('time-filter').value='all'; renderItems()",context);
  assert.doesNotMatch(element('items').innerHTML,/Known exploited/);
  vm.runInContext("$('search').value='does not exist'; renderItems()",context);
  assert.match(element('items').innerHTML,/No stories in this view/);
  assert.equal(vm.runInContext("safeLink('javascript:alert(1)')",context),'#');
  vm.runInContext("openStat('news')",context);
  assert.equal(vm.runInContext('view',context),'briefing');
  assert.equal(element('time-filter').value,'1');
  assert.equal(vm.runInContext('filteredItems().length',context),1);
  vm.runInContext("openStat('cves')",context);
  assert.equal(vm.runInContext('filteredItems().length',context),0,'Recent CVE shortcut counts publications, not recent KEV additions');
  vm.runInContext("disabled.delete('cisa'); openStat('kev')",context);
  assert.equal(element('source-filter').value,'cisa');
  assert.equal(element('exploited-only').checked,true);
  assert.equal(vm.runInContext('filteredItems().length',context),1,'KEV shortcut uses the KEV addition date');
  vm.runInContext("openStat('sources')",context);
  assert.equal(vm.runInContext('view',context),'sources');
  assert.match(element('items').innerHTML,/source-card/);
  vm.runInContext("setView('briefing')",context);
  assert.equal(vm.runInContext('statScope',context),null);
  vm.runInContext("setView('vulnerabilities'); $('time-filter').value='all'; $('sort-order').value='severity'; renderItems()",context);
  assert.match(element('items').innerHTML,/CVSS 9.8/);
  assert.equal(element('.threat-radar').hidden,true,'Map stays out of focused sections');
  assert.equal(element('sort-severity').hidden,false);
  vm.runInContext("fixtureExtra = {...data.items[0],id:'older-news',title:'Older story',published:'2020-01-01T00:00:00Z'}; data.items.push(fixtureExtra); setView('briefing'); $('time-filter').value='all'; $('sort-order').value='oldest'",context);
  assert.equal(vm.runInContext('filteredItems()[0].id',context),'older-news','Oldest-first sorting changes feed order');
  vm.runInContext("$('sort-order').value='newest'",context);
  assert.equal(vm.runInContext('filteredItems()[0].id',context),'news1');
  assert.equal(element('.threat-radar').hidden,false,'Overview retains the map');
  vm.runInContext("$('search').value='no match'; setView('briefing')",context);
  assert.equal(element('search').value,'','Section reset clears search');
  assert.equal(element('sort-order').value,'newest');
  failBookmarks = true;
  await vm.runInContext("toggleBookmark('cve:CVE-2026-12345')",context);
  assert.equal(vm.runInContext("saved.has('cve:CVE-2026-12345')",context), true, 'Failed saves keep the confirmed state');
  failBookmarks = false;
  serverSaved.clear();
  await vm.runInContext('syncBookmarks()',context);
  assert.equal(vm.runInContext('saved.size',context), 0, 'Changes on another device appear after sync');
  await vm.runInContext('syncBookmarks()',context);
  assert.equal(serverSaved.size, 0, 'Migrated bookmarks are not restored after another device removes them');
  return 'Frontend checks passed: migration, remote save failure, cross-device sync, filtering, CVE merging, recent KEV, saved CVEs, subscriptions, and safe output.';
})();
if (require.main === module) module.exports.then(console.log).catch(error => {console.error(error);process.exitCode=1;});
