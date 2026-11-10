const vm=require('vm'),fs=require('fs'),assert=require('assert');
const elements=new Map();
function el(id){if(!elements.has(id))elements.set(id,{value:'old',textContent:'old',hidden:false,disabled:false,replaceChildren(){this.cleared=true},reset(){for(const k of ['policy','blocked_terms','internal_domains','llm_url','llm_key','yandex_key'])el(k).value=''}});return elements.get(id)}
let downloads=0,initialResolve;
const context=vm.createContext({console,URL,URLSearchParams,setTimeout,fetch:()=>new Promise(r=>initialResolve=r),document:{getElementById:el,createElement:()=>({click(){downloads++},remove(){}}),body:{appendChild(){}}}});
vm.runInContext(fs.readFileSync('index.html','utf8').split('<script>')[1].split('</script>')[0],context);
(async()=>{
 vm.runInContext('showLogin()',context);
 for(const id of ['policy','blocked_terms','internal_domains','query','llm_key','yandex_key'])assert.equal(el(id).value,'');
 assert.equal(el('identity').textContent,'');assert(el('application').hidden);assert(el('connection_fields').disabled);
 el('identity').textContent='new session';initialResolve({ok:true});await new Promise(setImmediate);assert.equal(el('identity').textContent,'new session');
 let resolve;context.fetch=()=>new Promise(r=>resolve=r);
 const pending=vm.runInContext("request('/api/settings')",context);
 vm.runInContext('showLogin()',context);resolve({ok:true});await assert.rejects(pending,/Сеанс изменился/);
 let resolveJson;context.fetch=async()=>({ok:true,json:()=>new Promise(r=>resolveJson=r)});
 const jsonPending=vm.runInContext("api('/api/settings')",context);
 await new Promise(setImmediate);vm.runInContext('showLogin()',context);resolveJson({policy:'old secret'});await assert.rejects(jsonPending,/Сеанс изменился/);
 let resolveBlob;context.fetch=async()=>({ok:true,blob:()=>new Promise(r=>resolveBlob=r)});
 const exporting=el('export').onclick();await new Promise(setImmediate);vm.runInContext('showLogin()',context);resolveBlob({});await exporting;assert.equal(downloads,0);
 console.log('PASS: reset, stale HTTP response, stale JSON body, stale XLSX body, stale startup response (5 checks)');
})().catch(e=>{console.error(e);process.exitCode=1});
