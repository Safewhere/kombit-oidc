// Run with node BrowserLifecycle.test.cjs. Uses only Node built-ins.
const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
class Element { constructor(tag,cls,text){this.tag=tag;this.textContent=text||'';this.children=[];this.dataset={};} append(...v){this.children.push(...v);} replaceChildren(){this.children=[];} }
const flatten=e=>[e,...e.children.flatMap(flatten)];
(async()=>{
for(const [kind,file] of [['oidc',require('node:path').resolve(__dirname,'../WebAppNetCore/wwwroot/js/emergency-credential.js')]]) {
const source=fs.readFileSync(file,'utf8');new vm.Script(source);
assert(!source.includes('Forget browser copy'));
const name=kind==='oidc'?'list':'displayKeys';
const start=source.indexOf('    async function '+name+'()');
const end=source.indexOf(kind==='oidc'?"    bind('signout'":"    connect('exit'",start);
const code=source.slice(start,end);
for(const scenario of ['missing','versions','present','login','login-inactive','login-expired','failed-remove']){
 const container=new Element('ul');const binding={binding_id:'binding-123456',ec_id:'cred',expires_at:2000000000,status:'active'};
 let state={can_prepare:true,credentials:[binding]};let records=[];let calls=[],deleted=[];
 if(scenario==='versions')state.credentials.push({...binding,ec_id:'older'});
 if(scenario==='present'||scenario.startsWith('login'))records=[{...binding,emergency_credential:'test'}];
 if(scenario==='login-expired')records[0].expires_at=1;
 const mode=scenario.startsWith('login')?'login':'prepare';
 const ctx={document:{getElementById:()=>container},root:{dataset:{mode}},page:{dataset:{mode}},stored:async()=>records,storage:async()=>records,
 api:async(p)=>{calls.push(p);if(p==='status')return state;if(p==='login/status'||p==='login-status')return {active:scenario!=='login-inactive'};if(scenario==='failed-remove')throw Error('unavailable');state.credentials=[];return {};},
 send:async(p)=>{calls.push(p);if(p==='status')return state;if(p==='login/status'||p==='login-status')return {active:scenario!=='login-inactive'};if(scenario==='failed-remove')throw Error('unavailable');state.credentials=[];return {};},
 setPreparationState:()=>{},element:(...a)=>new Element(...a),badge:(a,b)=>new Element('span',a,b),
 button:(t,fn)=>Object.assign(new Element('button',null,t),{fn}),control:(t,fn)=>Object.assign(new Element('button',null,t),{fn}),
 statusLabels:{active:'Active'},deleteStoredBinding:async b=>deleted.push(b),message:()=>{},show:()=>{},confirm:()=>true,Date,Map};
 vm.createContext(ctx);vm.runInContext(code+`;globalThis.run=${name};`,ctx);await ctx.run();
 let nodes=flatten(container),buttons=nodes.filter(x=>x.tag==='button');
 if(['missing','versions','failed-remove'].includes(scenario)){
 assert.equal(buttons.length,1);assert.equal(buttons[0].textContent,'Remove key locally');assert(nodes.some(x=>x.textContent.includes('Browser copy missing')));
 if(scenario==='failed-remove'){await assert.rejects(buttons[0].fn());assert.equal(deleted.length,0);}
 else {await buttons[0].fn();assert.deepEqual(deleted,['binding-123456']);assert.equal(flatten(container).filter(x=>x.tag==='button').length,0);}
 } else if(scenario==='present')assert(!nodes.some(x=>x.textContent.includes('Browser copy missing')));
 else if(scenario==='login'){assert.equal(calls.length,1);assert.equal(buttons.length,1);assert.equal(buttons[0].textContent,'Log in with this key');} else {assert.equal(buttons.length,0);assert.equal(calls.length,scenario==='login-expired'?0:1);}
 console.log(kind+': '+scenario+' passed');
}
}
})().catch(e=>{console.error(e);process.exitCode=1});
