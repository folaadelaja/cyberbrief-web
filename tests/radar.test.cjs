const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {attrs:{},dataset:{},children:[],events:{},textContent:'',innerHTML:'',hidden:false,
    classList:{values:new Set(),toggle(k,v){if(v===undefined)v=!this.values.has(k);v?this.values.add(k):this.values.delete(k);},add(k){this.values.add(k);},contains(k){return this.values.has(k);}},
    setAttribute(k,v){this.attrs[k]=v;},replaceChildren(){this.children=[];},appendChild(v){this.children.push(v);},addEventListener(k,fn){this.events[k]=fn;}});
  return elements.get(id);
}
const world={countries:[{code:'US',name:'United States',path:'M0,0L1,0L1,1Z',x:200,y:150},{code:'NL',name:'Netherlands',path:'M2,2L3,2L3,3Z',x:500,y:120}]};
const state={reports:30,rows:[{ip:'8.8.8.8',country_code:'US',reports:20,targets:2},{ip:'1.1.1.1',country_code:'NL',reports:10,targets:1}],countries:[{code:'US',name:'United States',reports:20,sources:1},{code:'NL',name:'Netherlands',reports:10,sources:1}],last_success:new Date().toISOString(),window:'2026-11-18 UTC',unmapped_sources:0};
const context=vm.createContext({console,matchMedia:()=>({matches:false}),document:{hidden:false,getElementById:element,querySelector:element,createElementNS:(_,tag)=>({tag,attrs:{},children:[],setAttribute(k,v){this.attrs[k]=v;},appendChild(v){this.children.push(v);}}),addEventListener(){}},fetch:async url=>({ok:true,json:async()=>url==='/world-map.json'?world:state}),setInterval(){}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/radar.js'),'utf8'),context);
module.exports=(async()=>{
 await new Promise(r=>setImmediate(r));
 assert.equal(element('radar-reports').textContent,'30');
 assert.equal(element('map-countries').children.length,2);
 assert.equal(element('map-pulses').children.length,2);
 assert.match(element('radar-ranking').innerHTML,/United States/);
 assert.match(element('radar-window').textContent,/2026-11-18 UTC/);
 element('.native-radar').events.click({target:{closest:()=>({dataset:{country:'US'}})}});
 assert.equal(element('radar-region-title').textContent,'United States');
 assert.match(element('radar-ranking').innerHTML,/8.8.8.8/);
 element('radar-toggle').events.click();
 assert.equal(element('radar-toggle').textContent,'Resume animation');
 assert(element('.native-radar').classList.contains('animation-paused'));
 element('radar-reset').events.click();
 assert.equal(element('radar-region-title').textContent,'Observed source regions');
 return 'Native radar checks passed: local geometry, real counts, country selection, source details, and pause/reset controls.';
})();
if(require.main===module)module.exports.then(console.log).catch(e=>{console.error(e);process.exitCode=1;});
