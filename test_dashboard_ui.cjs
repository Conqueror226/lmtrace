/* Headless DOM contract checks, using Node only. This is not browser/visual QA. */
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const html = fs.readFileSync('web/dashboard.html','utf8');
class Classes {
  constructor(){this.values=new Set();}
  toggle(name,force){const add=force===undefined?!this.values.has(name):force;if(add)this.values.add(name);else this.values.delete(name);return add;}
  contains(name){return this.values.has(name);}
}
class Element {
  constructor(id=''){this.id=id;this.dataset={};this.classList=new Classes();this.listeners={};this.options=[];this.value='';this.disabled=false;this.hidden=false;this.textContent='';this._html='';this.attributes={};}
  set innerHTML(text){this._html=text;if(this.id.endsWith('select')||this.id==='filter-technique'){this.options=[...text.matchAll(/<option value="([^"]*)"/g)].map(m=>({value:m[1].replaceAll('&amp;','&'),disabled:false}));}}
  get innerHTML(){return this._html;}
  addEventListener(name,fn){this.listeners[name]=fn;}
  setAttribute(name,val){this.attributes[name]=val;}
  removeAttribute(name){delete this.attributes[name];}
  focus(){}
  append(){}
  remove(){}
  click(){this.listeners.click?.({target:this});}
  closest(){return this;}
  showModal(){this.open=true;}
  close(){this.open=false;}
}
const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element(m[1])]));
const views=Object.values(elements).filter(el=>el.id.startsWith('view-'));
const nav=['flow','recordings','experiments','analyze'].map(view=>{const el=new Element();el.dataset.view=view;return el;});
const handlers={};
const document={body:new Element('body'),getElementById:id=>{assert.ok(elements[id],`Missing DOM id ${id}`);return elements[id];},querySelectorAll:q=>q==='.view'?views:q==='[data-view]'?nav:[],addEventListener:(name,fn)=>handlers[name]=fn,createElement:()=>new Element()};
const location={protocol:'file:',hash:''};
const context={document,location,history:{replaceState:(_,__,hash)=>location.hash=hash},TextEncoder,Blob,URL,crypto:webcrypto,console,setTimeout,fetch:()=>Promise.reject(new Error('No API in standalone mode'))};
context.window=context;context.addEventListener=(name,fn)=>handlers[name]=fn;context.scrollTo=()=>{};
vm.createContext(context);
vm.runInContext(fs.readFileSync('web/dashboard-data.js','utf8'),context);
vm.runInContext(fs.readFileSync('web/dashboard.js','utf8'),context);
const ui=id=>elements[id];
const change=(id,value)=>{ui(id).value=String(value);ui(id).listeners.change();};
const clickData=dataset=>{const target=new Element();target.dataset=dataset;handlers.click({target});};
const stage=index=>clickData({step:String(index)});
function reset(index=0){change('case-select',index);handlers.hashchange();}
assert.match(ui('stage-panel').innerHTML,/Start with the original capture/);
stage(1);assert.match(ui('stage-panel').innerHTML,/Cyb3rWard0g/);assert.match(ui('stage-panel').innerHTML,/GruntHTTP2.exe/);
stage(2);assert.match(ui('stage-panel').innerHTML,/0xba93e3/);
stage(3);assert.match(ui('stage-panel').innerHTML,/172.18.39.5:54736/);assert.match(ui('stage-panel').innerHTML,/172.18.39.6:445/);
change('variant-select','4624 network logon');
assert.match(ui('conclusion-panel').innerHTML,/ARTIFACT/);
assert.doesNotMatch(ui('conclusion-panel').innerHTML,/route from WORKSTATION5/);
stage(2);assert.match(ui('stage-panel').innerHTML,/remote session is unproven/);
change('variant-select','Sysmon 3 connection');stage(3);
assert.match(ui('conclusion-panel').innerHTML,/SESSION/);assert.match(ui('stage-panel').innerHTML,/route is not corroborated/);
change('variant-select','4697 service install');stage(1);
assert.match(ui('stage-panel').innerHTML,/SCM pipe was accessed/);
assert.doesNotMatch(ui('stage-panel').innerHTML,/A service was registered/);
change('variant-select','5145 share access');
assert.match(ui('conclusion-panel').innerHTML,/ROUTE/);assert.match(ui('conclusion-panel').innerHTML,/No supported SCM observation/);
// All dataset/experiment/step states render without throwing.
let states=0;
for(let i=0;i<context.EVIDENCE_DATA.rows.length;i++){
  reset(i);
  for(const [name,v] of Object.entries(context.EVIDENCE_DATA.rows[i].variants)){
    if(name!=='baseline'&&!v.removed)continue;
    change('variant-select',name);
    for(let s=0;s<5;s++){stage(s);assert.ok(ui('stage-panel').innerHTML);states++;}
  }
}
reset(13);stage(1);assert.match(ui('stage-panel').innerHTML,/explorer.exe/);assert.match(ui('conclusion-panel').innerHTML,/NONE/);
reset(8);stage(2);
assert.match(ui('stage-panel').innerHTML,/Not recorded on this process event/);
assert.match(ui('stage-panel').innerHTML,/does not carry a SID/);
assert.equal(ui('local-analysis').hidden,true);
assert.equal(ui('hosted-analysis-note').hidden,false);
ui('present-button').click();assert.equal(document.body.classList.contains('presenting'),true);ui('present-button').click();
// Exact source bytes and large integers remain strings in the record viewer.
const r=context.EVIDENCE_DATA.rows[7];const record=Object.values(r.record_lookup)[0];
clickData({ref:record.ref,source:r.archive});
assert.equal(ui('record-dialog').open,true);assert.equal(ui('record-json').textContent,record.json);
ui('record-format').click();assert.equal(ui('record-json').textContent,record.raw_line);
ui('record-close').click();assert.equal(ui('record-dialog').open,false);
assert.doesNotMatch(html,/<iframe/);
console.log(`Dashboard DOM contracts passed: ${states} dataset/experiment/step states; attribution, missing evidence, raw-line viewing, presentation controls.`);
