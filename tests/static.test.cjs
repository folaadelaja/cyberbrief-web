const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(process.argv[2] || 'dist', 'app.js'), 'utf8');
const stamp = new Date().toISOString();
const fixture = {generated_at:stamp,interval_seconds:3600,items:[
 {id:'news1',source:'news',kind:'news',title:'Latest threat',summary:'<img onerror=alert(1)>',url:'https://example.com/article',published:stamp,category:'Threats'},
 {id:'news-old',source:'news',kind:'news',title:'Older story',summary:'Earlier reporting',url:'https://example.com/old',published:'2020-01-01T00:00:00Z',category:'Threats'},
 {id:'nvd:CVE-2026-12345',source:'nvd',kind:'cve',cve:'CVE-2026-12345',title:'Critical flaw',summary:'A flaw',url:'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',published:stamp,score:9.8},
 {id:'nvd:CVE-2026-54321',source:'nvd',kind:'cve',cve:'CVE-2026-54321',title:'Medium flaw',summary:'Another flaw',url:'https://nvd.nist.gov/vuln/detail/CVE-2026-54321',published:stamp,score:4.3}
],sources:[{id:'news',name:'News',last_success:stamp},{id:'nvd',name:'NVD',last_success:stamp}]};
function browser(storage = new Map()) {
 const elements = new Map(), state = {exported:null,failWrites:false};
 const element = id => {
  if (!elements.has(id)) elements.set(id,{value:id==='time-filter'?'7':['source-filter','severity-filter'].includes(id)?'all':'',hidden:false,textContent:'',innerHTML:'',checked:false,dataset:{},events:{},options:[{}],classList:{values:new Set(),toggle(k,v){if(v===undefined)v=!this.values.has(k);v?this.values.add(k):this.values.delete(k);},contains(k){return this.values.has(k);}},setAttribute(){},addEventListener(k,fn){this.events[k]=fn;},appendChild(o){this.options.push(o);},showModal(){},close(){},focus(){},click(){},scrollIntoView(){}});
  return elements.get(id);
 };
 class BrowserURL extends URL { static createObjectURL(blob){state.exported=blob;return 'blob:test';} static revokeObjectURL(){} }
 const context = vm.createContext({console,URL:BrowserURL,Blob,localStorage:{getItem:k=>storage.get(k)||null,setItem(k,v){if(state.failWrites)throw new Error('quota');storage.set(k,v);}},document:{getElementById:element,querySelector:element,querySelectorAll:()=>[],createElement:()=>element('created-link'),addEventListener(){},body:element('body')},fetch:async url=>{assert.equal(url,'./data/dashboard.json','Only the published JSON snapshot is requested');return {ok:true,json:async()=>JSON.parse(JSON.stringify(fixture))};},setTimeout(){},clearTimeout(){},setInterval(){},history:{replaceState(){}},location:{hash:''},window:{addEventListener(){}}});
 vm.runInContext(source, context);
 return {context,element,state,storage,run:code=>vm.runInContext(code,context)};
}
module.exports=(async()=>{
 const first=browser();await new Promise(r=>setImmediate(r));
 assert.match(first.element('items').innerHTML,/Latest threat/);
 assert.match(first.element('items').innerHTML,/&lt;img/);
 await first.run("toggleBookmark('news1')");
 assert.equal(first.run("saved.has('news1')"),true);
 const reload=browser(first.storage);await new Promise(r=>setImmediate(r));
 assert.equal(reload.run("saved.has('news1')"),true,'Reading list survives reload');
 first.run("setView('saved')");
 assert.equal(first.element('reading-tools').hidden,false);
 await first.element('export-reading').events.click();
 const exported=await first.state.exported.text();
 assert.equal(JSON.parse(exported).saved_items[0].id,'news1');
 const second=browser();await new Promise(r=>setImmediate(r));
 assert.equal(second.run('saved.size'),0,'A different browser starts with its own reading list');
 await second.element('import-reading').events.change({target:{files:[{size:exported.length,text:async()=>exported}],value:''}});
 assert.equal(second.run("saved.has('news1')"),true,'Export/import transfers saved snapshots between devices');
 const malicious=JSON.parse(exported);malicious.saved_items[0].url='javascript:alert(1)';
 const unsafe=JSON.stringify(malicious);
 await second.element('import-reading').events.change({target:{files:[{size:unsafe.length,text:async()=>unsafe}],value:''}});
 assert.match(second.element('toast').textContent,/unsafe article URL/);
 second.state.failWrites=true;
 await second.run("toggleBookmark('news1')");
 assert.equal(second.run("saved.has('news1')"),true,'Quota failure preserves confirmed saved state');
 second.state.failWrites=false;
 second.run("setView('briefing'); $('time-filter').value='all'; $('sort-order').value='oldest'");
 assert.equal(second.run('filteredItems()[0].id'),'news-old');
 second.run("setView('vulnerabilities'); $('sort-order').value='severity'");
 assert.equal(second.run('filteredItems()[0].score'),9.8);
 second.run("openStat('cves'); $('sort-order').value='oldest'");
 second.element('sort-order').events.change();
 assert.equal(second.run('statScope'),'published','Sorting preserves overview date scope');
 assert.equal(second.element('.threat-radar').hidden,true);
 return 'Static frontend passed: snapshot loading, escaping, persistent saves, independent browsers, export/import, unsafe import rejection, quota failure, sorting, and scope preservation.';
})();
if(require.main===module)module.exports.then(console.log).catch(error=>{console.error(error);process.exitCode=1;});
