const {test}=require('node:test'),assert=require('node:assert/strict');
const Threat=require('../../src/models/threat'),service=require('../../src/services/threatService');

test('an unmatched indicator returns Unknown without invented provider verdicts or score',async()=>{
 const original=Threat.findActive;Threat.findActive=async()=>null;
 try{
  const r=await service.lookup('example.com');
  assert.equal(r.reputation,'Unknown');assert.equal(r.score,null);assert.equal(r.malicious,0);assert.equal(r.total,1);
  assert.deepEqual(r.providers,[{name:'Internal blocklist',verdict:'Unknown'}]);assert.deepEqual(r.sources,[]);assert.deepEqual(r.timeline,[]);
 }finally{Threat.findActive=original}
});

test('an exact active blocklist hit is attributed only to the internal blocklist',async()=>{
 const original=Threat.findActive;Threat.findActive=async()=>({category:'Credential theft',created_at:new Date('2026-01-01T00:00:00Z')});
 try{
  const r=await service.lookup('evil.example');
  assert.equal(r.reputation,'Malicious');assert.equal(r.score,100);assert.equal(r.malicious,1);
  assert.deepEqual(r.sources,['Internal blocklist']);assert.deepEqual(r.categories,['Credential theft']);
 }finally{Threat.findActive=original}
});

test('only configured reputation sources appear in the provider overview',async()=>{
 const r=await service.overview();
 assert.deepEqual(r.providers.map(p=>p.name),['Internal blocklist']);assert.deepEqual(r.timeline,[]);
});
