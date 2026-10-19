const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('crypto');
const Attachment=require('../../src/models/attachment'),service=require('../../src/services/attachmentService');

test('unsupported file extensions are rejected before persistence',async()=>{
 const original=Attachment.insert;let inserts=0;Attachment.insert=async()=>{inserts++};
 try{await assert.rejects(service.analyze({dbId:1},{originalname:'payload.xyz',size:4,buffer:Buffer.from('data'),mimetype:'application/octet-stream'}),e=>e.status===415&&e.code==='UNSUPPORTED_FILE_TYPE');assert.equal(inserts,0)}
 finally{Attachment.insert=original}
});

test('supported file analysis hashes and persists metadata only with scanner state explicit',async()=>{
 const original=Attachment.insert;let saved;Attachment.insert=async x=>{saved=x};
 const bytes=Buffer.from('%PDF-1.7 test');
 try{
  const r=await service.analyze({dbId:7},{originalname:'invoice.pdf',size:bytes.length,buffer:bytes,mimetype:'application/pdf'});
  assert.equal(r.sha256,crypto.createHash('sha256').update(bytes).digest('hex'));assert.equal(saved.userId,7);assert.equal(saved.sha256,r.sha256);
  assert.deepEqual(r.scanEngine,{name:'External malware scanner',configured:false,status:'unavailable',detail:'No external malware-scanning engine is configured; this result uses static heuristics only.'});
 }finally{Attachment.insert=original}
});

test('empty uploads are rejected',async()=>{
 await assert.rejects(service.analyze({dbId:1},{originalname:'empty.pdf',size:0,buffer:Buffer.alloc(0)}),e=>e.status===400&&e.code==='EMPTY_FILE');
});
