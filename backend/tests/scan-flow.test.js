// Scan lifecycle against a STUB analysis service (a local HTTP server returning a real engine report fixture).
// Covers: async creation, persistence of every table + the raw engine report, failures, timeouts, deletion mid-scan, stale scans, concurrency.
const http=require('http'),fs=require('fs'),path=require('path');
const FIXTURE=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures','report.phishing_with_ml.json'),'utf8'));
const stub={mode:'ok',delay:0,calls:[],active:0,peak:0};
const server=http.createServer((req,res)=>{
 let body='';req.on('data',c=>body+=c);req.on('end',()=>{
  stub.calls.push({url:req.url,key:req.headers['x-api-key'],body:body?JSON.parse(body):null});stub.active++;stub.peak=Math.max(stub.peak,stub.active);
  const done=()=>{stub.active--};res.on('close',done);
  if(stub.mode==='hang')return;
  setTimeout(()=>{if(stub.mode==='500'){res.writeHead(500,{'Content-Type':'application/json'});return res.end('{"detail":"Traceback (most recent call last): secret"}')}
   res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(FIXTURE))},stub.delay);});
});
// Node 24 may complete an ephemeral listen asynchronously. Use a dedicated
// loopback port so the URL can be configured before loading the application.
const port=43127;
server.listen(port,'127.0.0.1');
Object.assign(process.env,{ANALYSIS_SERVICE_URL:`http://127.0.0.1:${port}`,ANALYSIS_API_KEY:'stub-key',ANALYSIS_TIMEOUT_MS:'600',ANALYSIS_CONCURRENCY:'2',ANALYSIS_STALE_SECONDS:'2'});
const assert=require('node:assert/strict'),{test,before,after,beforeEach}=require('node:test'),h=require('./helpers');
const {call,db,waitDone}=h;let tok,uid;
before(async()=>{await h.start();const r=await call('POST','/auth/register',{name:'Flow User',email:'flow@test.dev',password:'Passw0rd!long'});tok=r.data.token;uid=(await db.query("select id from users where email='flow@test.dev'")).rows[0].id});
after(async()=>{await h.stop();server.close()});
beforeEach(()=>{stub.mode='ok';stub.delay=0;stub.calls.length=0;stub.peak=0});
const rowsOf=async(t,n)=>(await db.query(`select count(*)::int n from ${t} where scan_id=$1`,[n])).rows[0].n;
const idOf=p=>+p.slice(2)-1000;

test('a scan is created immediately and analysed in the background',async()=>{
 stub.delay=300;
 const c=await call('POST','/scans',{url:'https://paypa1-secure-login.xyz/verify'},tok);assert.equal(c.status,201);
 const first=await call('GET',`/scans/${c.data.scanId}/status`,null,tok);assert.equal(first.data.status,'running');assert.ok(first.data.progress<100);
 assert.equal((await call('GET',`/analysis/${c.data.scanId}/report`,null,tok)).status,409); // not ready yet
 const fin=await waitDone(c.data.scanId,tok);assert.deepEqual([fin.status,fin.progress],['completed',100]);
});
test('a completed scan stores the engine result in every table and the raw report',async()=>{
 const c=await call('POST','/scans',{url:'https://paypa1-secure-login.xyz/verify?next=http://evil.com'},tok),id=c.data.scanId,n=idOf(id);await waitDone(id,tok);
 assert.deepEqual(stub.calls.map(x=>[x.url,x.key,x.body.url]),[['/analyze','stub-key','https://paypa1-secure-login.xyz/verify?next=http://evil.com']]);
 for(const t of ['scan_results','url_indicators','domain_indicators','tls_analysis','website_analysis','risk_assessments','analysis_reports'])assert.equal(await rowsOf(t,n),1,t);
 assert.ok(await rowsOf('threat_intelligence_results',n)>=1);assert.ok(await rowsOf('recommendations',n)>=1);assert.equal(await rowsOf('brand_matches',n),1);
 const raw=(await db.query('select report,schema_version from analysis_reports where scan_id=$1',[n])).rows[0];assert.equal(raw.schema_version,'1.0');assert.equal(raw.report.risk.score,FIXTURE.risk.score);
 const sr=(await db.query('select model_name,prediction from scan_results where scan_id=$1',[n])).rows[0];assert.deepEqual(sr,{model_name:'xgboost',prediction:'Phishing'});
 const list=(await call('GET','/scans',null,tok)).data.find(s=>s.id===id);assert.equal(list.score,FIXTURE.risk.score);assert.equal(list.status,'Completed');
 const rep=await call('GET',`/analysis/${id}/report`,null,tok);assert.equal(rep.status,200);assert.equal(rep.data.engine.modules.website.status,'ok');assert.equal(rep.data.brand.name,'PayPal');assert.ok(rep.data.web.some(r=>r.label==='External form action'&&r.status==='bad'));
 assert.equal((await db.query('select count(*)::int n from scans where id=$1 and status=$2 and error_message is null',[n,'Completed'])).rows[0].n,1);
});
test('an upstream error fails the scan with a safe message and no internal details',async()=>{
 stub.mode='500';const c=await call('POST','/scans',{url:'https://example.org/a'},tok),id=c.data.scanId;
 const s=await waitDone(id,tok);assert.equal(s.status,'failed');assert.equal(s.error,'The analysis failed');assert.ok(!/Traceback|secret/.test(JSON.stringify(s)));
 const r=await call('GET',`/analysis/${id}/report`,null,tok);assert.equal(r.status,422);assert.ok(!/Traceback/.test(JSON.stringify(r.body)));
 assert.equal((await call('GET','/scans',null,tok)).data.find(x=>x.id===id).status,'Failed');
 const n=idOf(id);for(const t of ['scan_results','risk_assessments','analysis_reports'])assert.equal(await rowsOf(t,n),0,t);
});
test('failed scans are excluded from dashboard statistics',async()=>{
 const before=(await call('GET','/scans/overview',null,tok)).data.stats.total;
 stub.mode='500';await waitDone((await call('POST','/scans',{url:'https://example.org/b'},tok)).data.scanId,tok);
 assert.equal((await call('GET','/scans/overview',null,tok)).data.stats.total,before);
});
test('a hanging analysis service times out',async()=>{
 stub.mode='hang';const t=Date.now(),c=await call('POST','/scans',{url:'https://example.org/c'},tok);
 const s=await waitDone(c.data.scanId,tok);assert.deepEqual([s.status,s.error],['failed','The analysis timed out']);assert.ok(Date.now()-t<5000);
});
test('invalid URLs are rejected before any job is queued',async()=>{
 const n=stub.calls.length;for(const url of ['javascript:alert(1)','http://127.0.0.1/x','http://10.0.0.5/'])assert.equal((await call('POST','/scans',{url},tok)).status,400,url);assert.equal(stub.calls.length,n);
});
test('deleting a scan while it is still analysing leaves no orphaned rows',async()=>{
 stub.delay=400;const c=await call('POST','/scans',{url:'https://example.org/d'},tok),id=c.data.scanId,n=idOf(id);
 assert.equal((await call('DELETE',`/scans/${id}`,null,tok)).status,200);
 await new Promise(r=>setTimeout(r,900));
 assert.equal((await db.query('select count(*)::int n from scans where id=$1',[n])).rows[0].n,0);for(const t of ['scan_results','analysis_reports','risk_assessments'])assert.equal(await rowsOf(t,n),0,t);
 assert.equal((await call('GET',`/scans/${id}/status`,null,tok)).status,404);
});
test('scans stuck in Running are failed when polled, and by the startup reaper',async()=>{
 const old=async()=>(await db.query("insert into scans(user_id,target_url,host,status,created_at) values($1,'https://stuck.example/','stuck.example','Running',now()-interval '1 hour') returning id",[uid])).rows[0].id;
 const a=await old(),s=await call('GET',`/scans/S-${1000+a}/status`,null,tok);assert.deepEqual([s.data.status,s.data.error],['failed','The analysis timed out']);
 assert.equal((await db.query('select status from scans where id=$1',[a])).rows[0].status,'Failed');
 await old();await old();assert.equal(await require('../src/models/scan').failStale(2),2);
 assert.equal((await db.query("select count(*)::int n from scans where status='Running' and created_at<now()-interval '1 minute'")).rows[0].n,0);
});
test('analysis concurrency is bounded by ANALYSIS_CONCURRENCY',async()=>{
 stub.delay=150;const ids=[];for(let i=0;i<6;i++)ids.push((await call('POST','/scans',{url:`https://example.org/p${i}`},tok)).data.scanId);
 for(const id of ids)assert.equal((await waitDone(id,tok)).status,'completed');assert.ok(stub.peak<=2,`peak concurrency ${stub.peak}`);assert.equal(stub.calls.length,6);
});
test("another user cannot poll or delete someone else's running scan",async()=>{
 stub.delay=300;const id=(await call('POST','/scans',{url:'https://example.org/e'},tok)).data.scanId;
 const b=await call('POST','/auth/register',{name:'Other User',email:'other@test.dev',password:'Passw0rd!long'});
 assert.equal((await call('GET',`/scans/${id}/status`,null,b.data.token)).status,404);assert.equal((await call('POST',`/scans/${id}/cancel`,null,b.data.token)).status,404);await waitDone(id,tok);
});
