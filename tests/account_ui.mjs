import {JSDOM} from '../examples/mcp-client/node_modules/jsdom/lib/api.js';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
const wait=async()=>{await new Promise(r=>setTimeout(r,20));};
function fixture(){
 const dom=new JSDOM(readFileSync('dashboard/account.html','utf8'),{url:'https://example.test/account',runScripts:'outside-only'});
 const calls=[];
 dom.window.fetch=async(path,options)=>{
  calls.push({path,options});
  const data=path==='/account/session'?{account_id:'a',csrf_token:'csrf',spaces:[{space_id:'s',display_name:'<img onerror=alert(1)>'}]}:
   path.endsWith('/inspect')?{display_name:'<script>untrusted</script>'}:
   path.endsWith('/list')?{devices:[{device_id:'d',display_name:'Device',state:'consumed'}],has_more:false}:{};
  return {ok:true,json:async()=>({ok:true,data})};
 };
 dom.window.eval(readFileSync('dashboard/account.js','utf8'));return {dom,calls,doc:dom.window.document};
}
test('account refresh actually refetches session and renders names as text',async()=>{
 const {dom,calls,doc}=fixture();await wait();const n=calls.length;
 doc.getElementById('refresh').click();await wait();assert.equal(calls.length,n+1);assert.equal(calls.at(-1).path,'/account/session');
 assert.equal(doc.querySelectorAll('#spaces img').length,0);assert.match(doc.getElementById('spaces').textContent,/<img/);dom.window.close();
});
test('approval requires inspection and device code edits invalidate it',async()=>{
 const {dom,calls,doc}=fixture();await wait();const input=doc.getElementById('device-code');
 assert.equal(doc.getElementById('approve').disabled,true);input.value='1111';doc.getElementById('inspect').click();await wait();
 assert.equal(doc.getElementById('approve').disabled,false);assert.equal(doc.querySelectorAll('#device-info script').length,0);
 input.value='2222';input.dispatchEvent(new dom.window.Event('input'));assert.equal(doc.getElementById('approve').disabled,true);
 assert.equal(calls.at(-1).options.headers['X-Waypost-CSRF'],'csrf');dom.window.close();
});
test('device listing revokes only selected device without secrets',async()=>{
 const {dom,calls,doc}=fixture();await wait();doc.getElementById('devices').click();await wait();
 doc.querySelector('#device-list button').click();await wait();assert.equal(calls.at(-1).path,'/account/devices/revoke');
 assert.deepEqual(JSON.parse(calls.at(-1).options.body),{device_id:'d'});dom.window.close();
});
