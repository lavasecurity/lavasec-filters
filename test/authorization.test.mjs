import assert from 'node:assert/strict';
import test from 'node:test';
import {generateKeyPairSync, sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {signCatalog, verifyCatalog, definitions, CONTEXT} from '../src/authorization.mjs';
const now = 1800000000;
const {privateKey, publicKey} = generateKeyPairSync('ed25519');
const pem = privateKey.export({format: 'pem', type: 'pkcs8'});
const pins = {test: Buffer.from(publicKey.export({format: 'jwk'}).x, 'base64url').toString('base64')};
const source = {id:'example', name:'Example', category:'security', risk_level:'low', default_enabled:true,
  license_name:'Test', attribution:'Fixture only', project_url:'https://example.com/',
  source_url:'https://example.com/domains.txt', redistribution_mode:'source_url_only', parse_format:'plain_domains',
  license_text_url:null, notice_url:null, version_id:'v1', entry_count:1, byte_size:12,
  source_hash:'a'.repeat(64), normalized_hash:'a'.repeat(64),
  accepted_source_hashes:[{sha256:'a'.repeat(64),status:'accepted'}], published_at:'2027-01-15T08:00:00Z'};
const candidate = {schema_version:2,catalog_version:'20270115T080000Z',generated_at:'2027-01-15T08:00:00Z',sources:[source],guardrails:[]};
const approved = {revision:1,sources:definitions([source]),guardrails:[],withdrawn_sources:[]};
function signed(c = candidate, p = approved, options = {}) { return signCatalog(c,p,pem,'test',{now,...options}); }
function check(c, options = {}) { return verifyCatalog(c,pins,{now,...options}); }
function copy(c) { return structuredClone(c); }
function resign(c, mutate) {
  const value=copy(c), payload=JSON.parse(Buffer.from(value.catalog_authorization.payload,'base64'));
  mutate(payload); const bytes=Buffer.from(JSON.stringify(payload));
  value.catalog_authorization.payload=bytes.toString('base64');
  value.catalog_authorization.signature=sign(null,Buffer.concat([CONTEXT,bytes]),privateKey).toString('base64');
  return value;
}
test('signed schema-2 document preserves legacy fields',()=>{
 const result=signed(); assert.equal(check(result).revision,1);
 for(const key of Object.keys(candidate)) assert.deepEqual(result[key],candidate[key]);
});
test('approval is definition-level; provider observations may rotate',()=>{
 const value=copy(signed()); Object.assign(value.sources[0],{source_hash:'b'.repeat(64),version_id:'v2',entry_count:99});
 assert.equal(check(value).sources[0].source_url,source.source_url);
});
test('missing, unknown, malformed and tampered signatures fail',()=>{
 assert.throws(()=>check(candidate)); assert.throws(()=>verifyCatalog(signed(),{}, {now}));
 for(const field of ['signature','payload']) {const value=copy(signed());value.catalog_authorization[field]='AAAA';assert.throws(()=>check(value));}
 const value=copy(signed()); value.catalog_authorization.format=2;assert.throws(()=>check(value));
});
test('every source policy field is bound, including membership and tier',()=>{
 for(const field of ['source_url','parse_format','default_enabled','redistribution_mode','name','license_name']){
  const value=copy(signed()); value.sources[0][field]=field==='default_enabled'?false:field==='source_url'?'https://attacker.example/list':'changed';assert.throws(()=>check(value),field);
 }
 for(const mutate of [c=>c.sources.pop(),c=>c.sources.push({...source,id:'extra'}),c=>{c.guardrails=c.sources;c.sources=[];}]){
  const value=copy(signed());mutate(value);assert.throws(()=>check(value));
 }
});
test('signer refuses a publisher candidate different from independent approval',()=>{
 assert.throws(()=>signed({...candidate,sources:[]}));
 assert.throws(()=>signed({...candidate,sources:[{...source,source_url:'https://attacker.example/list'}]}));
});
test('expired, future, overlong and wrong-purpose authorizations fail',()=>{
 const value=signed();assert.throws(()=>check(value,{now:now-1}));assert.throws(()=>check(value,{now:now+7*86400}));
 assert.throws(()=>signed(candidate,approved,{validity:32*86400}));
 for(const mutate of [p=>p.purpose='other',p=>p.key_id='other',p=>p.revision=0,p=>p.format=2]) assert.throws(()=>check(resign(value,mutate)));
});
test('revision replay, same-revision definition swaps and renewal rollback fail',()=>{
 const value=signed(), renewed=signed(candidate,approved,{now:now+1});
 assert.doesNotThrow(()=>check(renewed,{now:now+1,previous:value.catalog_authorization}));
 assert.throws(()=>check(value,{now:now+1,previous:renewed.catalog_authorization}));
 const v2=signed(candidate,{...approved,revision:2});assert.throws(()=>check(value,{previous:v2.catalog_authorization}));
 const changedSource={...source,name:'Changed'},changed=signed({...candidate,sources:[changedSource]}, {...approved,sources:definitions([changedSource])});
 assert.throws(()=>check(changed,{previous:value.catalog_authorization}));
});
test('withdrawal is explicit, cumulative and cannot overlap active entries',()=>{
 const withdrawn=signed({...candidate,sources:[],withdrawn_sources:['example']},{revision:2,sources:[],guardrails:[],withdrawn_sources:['example']});
 check(withdrawn,{previous:signed().catalog_authorization});
 assert.throws(()=>check(signed(candidate,{...approved,revision:3}),{previous:withdrawn.catalog_authorization}));
 assert.throws(()=>signed({...candidate,withdrawn_sources:['example']},{...approved,withdrawn_sources:['example']}));
});
test('case-colliding definitions and withdrawals fail',()=>{
 assert.throws(()=>signed({...candidate,sources:[source,{...source,id:'EXAMPLE'}]}, {...approved,sources:[source,{...source,id:'EXAMPLE'}]}));
 assert.throws(()=>signed({...candidate,withdrawn_sources:['Other','other']},{...approved,withdrawn_sources:['Other','other']}));
});
test('cross-language fixture verifies with its public test pin',()=>{
 const fixture=JSON.parse(readFileSync(new URL('../fixtures/catalog-v1.json',import.meta.url)));
 verifyCatalog(fixture.catalog,fixture.pins,{now:fixture.now});
});
test('retired pins verify checkpoints but cannot authorize incoming catalogs',()=>{
 const nextKey=generateKeyPairSync('ed25519');
 const nextPins={next:Buffer.from(nextKey.publicKey.export({format:'jwk'}).x,'base64url').toString('base64')};
 const previous=signed().catalog_authorization;
 const next=signCatalog(candidate,{...approved,revision:2},nextKey.privateKey.export({format:'pem',type:'pkcs8'}),'next',
  {now,pins:nextPins,retiredKeys:pins,previous});
 assert.equal(verifyCatalog(next,nextPins,{now,previous,retiredKeys:pins}).revision,2);
 assert.throws(()=>verifyCatalog(next,nextPins,{now,previous}));
 assert.throws(()=>verifyCatalog(signed(),nextPins,{now,retiredKeys:pins}));
});
test('signer supplies approved withdrawals when the operational candidate omits them',()=>{
 const value=signed({...candidate,sources:[]},{revision:2,sources:[],guardrails:[],withdrawn_sources:['example']});
 assert.deepEqual(value.withdrawn_sources,['example']);
 assert.doesNotThrow(()=>check(value,{previous:signed().catalog_authorization}));
 assert.throws(()=>signed({...candidate,sources:[],withdrawn_sources:[]},
  {revision:2,sources:[],guardrails:[],withdrawn_sources:['example']}));
});
