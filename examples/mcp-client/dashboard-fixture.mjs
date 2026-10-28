import {JSDOM} from 'jsdom';
import assert from 'node:assert/strict';

// Exercise the assets served by this runtime, including Worker fingerprinted
// scripts and their locale URLs, instead of mixing source files with HTTP assets.
export async function loadDashboard(origin) {
  const response=await fetch(new URL('/dashboard',origin));
  assert.equal(response.status,200,'Dashboard HTML must load');
  assert.match(response.headers.get('content-type')||'',/text\/html/);
  const html=await response.text(),dom=new JSDOM(html,{url:response.url});
  try {
    const scripts=[];
    for(const element of dom.window.document.querySelectorAll('script[src]')) {
      const url=new URL(element.src);
      assert.equal(url.origin,new URL(origin).origin,'Dashboard scripts must stay on the test service');
      const asset=await fetch(url);
      assert.equal(asset.status,200,'Dashboard script must load');
      assert.match(asset.headers.get('content-type')||'',/(?:java|ecma)script/);
      scripts.push(await asset.text());
    }
    assert(scripts.length>0,'Dashboard must reference executable scripts');
    return {html,scripts};
  } finally {dom.window.close();}
}
