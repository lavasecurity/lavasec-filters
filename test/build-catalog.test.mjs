import {checkRevision} from '../src/check-revision.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {buildCatalog, clientIndex, validateCanonical} from '../src/build-catalog.mjs';
import {loadCanonical,assembleInventory} from '../src/inventory-source.mjs';
const canonical=loadCanonical();
test('canonical inventory alone defines all membership and policy', () => {
  const fake = {...canonical.sources[0], name:'publisher override', default_enabled:true,
    version_id:'observation', entry_count:42};
  const output = buildCatalog(canonical, {sources:[fake,{...fake,id:'injected'}]});
  assert.equal(output.sources.length, canonical.sources.length);
  assert.equal(output.sources.find(s=>s.id===fake.id).name,canonical.sources[0].name);
  assert.equal(output.sources.find(s=>s.id===fake.id).entry_count,42);
  assert(!output.sources.some(s=>s.id==='injected'));
});
test('missing, duplicate or differently sourced observations cannot change membership', () => {
  for (const sources of [[],[{...canonical.sources[0],source_url:'https://evil.example',entry_count:42}],
    [canonical.sources[0],canonical.sources[0]]]) {
    const output=buildCatalog(canonical,{sources});
    assert.equal(output.sources.length,canonical.sources.length);
    assert.equal(output.sources.find(s=>s.id===canonical.sources[0].id).entry_count,0);
  }
});
test('client index is a generated projection of the same canonical definitions', () => {
  const result=clientIndex(canonical);
  for (const [i,s] of result.sources.entries()) {
    assert.equal(s.source_url,canonical.sources[i].source_url);
    assert(!Object.hasOwn(s,'default_enabled'));
    assert.equal(s.license,canonical.sources[i].license_name);
  }
  assert(result.sources.every(s=>s.redistribution_mode==='source_url_only'));
  assert(!JSON.stringify(canonical).includes('default_enabled'));
});

test('canonical edits preserve source-only and legal default policies',()=>{
  for (const change of [s=>s.redistribution_mode='mirror',s=>s.default_enabled=true,
    s=>{s.license_name='GPL-3.0';s.license_text_url=null;}]){
    const bad=structuredClone(canonical);change(bad.sources[0]);assert.throws(()=>validateCanonical(bad));
  }
});

test('reviewed definition edits need revision bumps and all removals need tombstones',()=>{
  const changed=structuredClone(canonical);changed.sources[0].name='New display name';
  assert.throws(()=>checkRevision(canonical,changed));changed.revision++;checkRevision(canonical,changed);
  const removed=changed.sources.shift();assert.throws(()=>checkRevision(canonical,changed));
  changed.withdrawn_sources.push(removed.id);checkRevision(canonical,changed);
  const resurrected=structuredClone(canonical);resurrected.revision=changed.revision+1;
  assert.throws(()=>checkRevision(changed,resurrected));
});

test('legacy selection hint is unsigned compatibility data and is never imported',()=>{
  const c=buildCatalog(canonical,{sources:[{...canonical.sources[0],default_enabled:true}]});
  assert(c.sources.every(s=>s.default_enabled===false));
});

test('simple list fields cannot be overridden by supporting metadata',()=>{
  const list={id:'example',name:'Example',url:'https://example.com/list',category:'security'};
  const index={revision:1,withdrawn_sources:[],lists:[list]};
  assert.throws(()=>assembleInventory(index,{},[]));
  assert.throws(()=>assembleInventory(index,{example:{source_url:'https://evil.example'}},[]));
  assert.throws(()=>assembleInventory({...index,lists:[{...list,default_enabled:true}]},{example:{}},[]));
});
