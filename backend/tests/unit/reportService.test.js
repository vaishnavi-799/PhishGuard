const {test}=require('node:test'),assert=require('node:assert/strict');
const Report=require('../../src/models/report'),scans=require('../../src/services/scanService'),analysis=require('../../src/services/analysisService'),service=require('../../src/services/reportService');
const sample={scan:{id:'S-1001',target:'https://example.test'},url:[{label:'URL length',value:'20'}],why:[{text:'No blocklist hit'}],actions:[],domain:[],ssl:[],web:[],brand:{},intel:[],ml:{},shap:[]};

test('report creation stores a snapshot of the complete analysis',async()=>{
 const originals={getAccessible:scans.getAccessible,report:analysis.report,create:Report.create};let saved;
 scans.getAccessible=async()=>({id:1,status:'Completed'});analysis.report=async()=>sample;Report.create=async x=>(saved=x,{id:'R-2001',data:x.reportData});
 try{const r=await service.create({dbId:2},'S-1001');assert.deepEqual(saved.reportData,sample);assert.equal(saved.format,'json');assert.ok(saved.sizeKb>0);assert.deepEqual(r.data,sample)}
 finally{scans.getAccessible=originals.getAccessible;analysis.report=originals.report;Report.create=originals.create}
});

test('JSON and CSV downloads use only the requesting user\'s saved report',async()=>{
 const original=Report.findForUser;let owner;
 Report.findForUser=async(id,uid)=>{owner=uid;return{id:'R-2001',scanId:'S-1001',data:sample}};
 try{
  const json=await service.download({dbId:7},'R-2001','json');assert.equal(owner,7);assert.equal(json.filename,'phishguard-R-2001.json');assert.deepEqual(JSON.parse(json.body),sample);
  const csv=await service.download({dbId:9},'R-2001','csv');assert.equal(owner,9);assert.match(csv.body,/"section","item","evidence"/);assert.match(csv.body,/URL length/);
 }finally{Report.findForUser=original}
});

test('invalid formats are rejected',async()=>{
 await assert.rejects(service.download({dbId:1},'R-2001','pdf'),e=>e.status===400&&e.code==='INVALID_FORMAT');
});
