// Integration tests against a REAL PostgreSQL database. Requires TEST_DATABASE_URL (db name must contain "test").
// WARNING: wipes that database. Run: npm test
const crypto=require('crypto'),assert=require('node:assert/strict'),{test,before,after}=require('node:test');
const url=process.env.TEST_DATABASE_URL;
if(!url||!/test/i.test(new URL(url).pathname)){console.error('Set TEST_DATABASE_URL to a disposable database whose name contains "test"');process.exit(1)}
Object.assign(process.env,{DATABASE_URL:url,NODE_ENV:'test',LOG_LEVEL:'error',RATE_LIMIT_MAX:'100000',AUTH_RATE_LIMIT_MAX:'100000',REGISTER_RATE_LIMIT_MAX:'100000',BCRYPT_ROUNDS:'4'});
process.env.JWT_SECRET=process.env.JWT_SECRET||crypto.randomBytes(32).toString('hex');
const db=require('../src/config/db'),migrate=require('../src/db/migrate'),app=require('../src/app'),bcrypt=require('bcryptjs');
let server,base;const tok={};
const call=async(method,path,body,token)=>{const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:body?JSON.stringify(body):undefined});let j=null;try{j=await r.json()}catch{}return{status:r.status,body:j,data:j&&j.data}};
const waitDone=async(id,t)=>{for(let i=0;i<200;i++){const s=await call('GET',`/scans/${id}/status`,null,t);if(s.data&&s.data.status!=='running')return s.data;await new Promise(r=>setTimeout(r,50))}throw new Error('scan did not finish')};
const count=async(t,id)=>(await db.query(`select count(*)::int n from ${t} where scan_id=$1`,[id])).rows[0].n;
const mkUser=async(email,role)=>{await db.query('insert into users(role_id,name,email,password_hash) values((select id from roles where name=$1),$2,$3,$4)',[role,role+' user',email,await bcrypt.hash('Passw0rd!long',4)])};
before(async()=>{await db.query('drop schema public cascade');await db.query('create schema public');await migrate.up();server=app.listen(0);base=`http://127.0.0.1:${server.address().port}/api`});
after(async()=>{await require('../src/services/scanService').jobs.drain();server&&server.close();await db.pool.end()});

test('schema: all required tables exist and roles are seeded',async()=>{
 const need=['users','roles','scans','scan_results','url_indicators','domain_indicators','tls_analysis','website_analysis','brand_matches','threat_intelligence_results','risk_assessments','recommendations','reports','audit_logs'];
 const have=(await db.query("select table_name from information_schema.tables where table_schema='public'")).rows.map(r=>r.table_name);
 for(const t of need)assert.ok(have.includes(t),`missing table ${t}`);
 assert.equal((await db.query('select count(*)::int n from roles')).rows[0].n,4)});
test('constraints: plaintext passwords and bad data are rejected by the database',async()=>{
 await assert.rejects(db.query("insert into users(role_id,name,email,password_hash) values(1,'Plain Pw','plain@x.test','hunter2hunter2')"),/users_password_bcrypt/);
 await assert.rejects(db.query("insert into users(role_id,name,email,password_hash) values(1,'Bad Email','UPPER@X.test','$2a$04$'||repeat('a',53))"),/users_email_lower/);
 await assert.rejects(db.query("insert into risk_assessments(scan_id,score,category) values(999999,150,'x')"),/risk_score_range|foreign key/)});
test('auth: register, duplicate, login, wrong password, me; password stored as bcrypt',async()=>{
 const r=await call('POST','/auth/register',{name:'Alice Test',email:'Alice@Test.dev',password:'Passw0rd!long'});assert.equal(r.status,201);tok.alice=r.data.token;assert.equal(r.data.user.email,'alice@test.dev');assert.equal(r.data.user.role,'user');
 assert.equal((await call('POST','/auth/register',{name:'Alice Again',email:'alice@test.dev',password:'Passw0rd!long'})).status,409);
 assert.equal((await call('POST','/auth/register',{name:'Weak',email:'weak@test.dev',password:'short'})).status,400);
 assert.equal((await call('POST','/auth/login',{email:'alice@test.dev',password:'wrong-password1'})).status,401);
 const l=await call('POST','/auth/login',{email:'alice@test.dev',password:'Passw0rd!long'});assert.equal(l.status,200);assert.equal((await call('GET','/auth/me',null,l.data.token)).data.user.name,'Alice Test');
 const h=(await db.query("select password_hash from users where email='alice@test.dev'")).rows[0].password_hash;assert.match(h,/^\$2[aby]\$/);assert.ok(!h.includes('Passw0rd'));
 assert.equal((await call('GET','/scans')).status,401)});
test('scans CRUD: create persists every analysis table; report renders; delete cascades',async()=>{
 const c=await call('POST','/scans',{url:'https://secure-paypa1-login.com/verify'},tok.alice);assert.equal(c.status,201);const id=c.data.scanId,n=+id.slice(2)-1000;assert.equal((await waitDone(id,tok.alice)).status,'completed');
 for(const t of ['scan_results','url_indicators','domain_indicators','tls_analysis','website_analysis','risk_assessments'])assert.equal(await count(t,n),1,t);
 assert.ok(await count('threat_intelligence_results',n)>=1);assert.ok(await count('recommendations',n)>=1);assert.equal(await count('brand_matches',n),1);
 assert.equal((await call('POST','/scans',{url:'javascript:alert(1)'},tok.alice)).status,400);assert.equal((await call('POST','/scans',{url:'http://192.168.1.1'},tok.alice)).status,400);
 const list=await call('GET','/scans',null,tok.alice);assert.equal(list.data.length,1);assert.equal(list.data[0].id,id);assert.ok(list.data[0].score>=60);
 assert.ok((await call('GET',`/scans/${id}/status`,null,tok.alice)).data.status);
 const rep=await call('GET',`/analysis/${id}/report`,null,tok.alice);assert.equal(rep.status,200);for(const k of ['scan','why','actions','url','domain','ssl','web','brand','intel','ml','shap'])assert.ok(k in rep.data,k);assert.equal(rep.data.scan.id,id);assert.ok(rep.data.shap.length>0);
 const ov=await call('GET','/scans/overview',null,tok.alice);assert.equal(ov.data.stats.total,1);
 const del=await call('DELETE',`/scans/${id}`,null,tok.alice);assert.equal(del.status,200);
 for(const t of ['scan_results','url_indicators','domain_indicators','tls_analysis','website_analysis','risk_assessments','brand_matches','threat_intelligence_results','recommendations'])assert.equal(await count(t,n),0,`${t} not cascaded`);
 assert.equal((await call('GET',`/analysis/${id}/report`,null,tok.alice)).status,404)});
test('ownership: another user cannot read or delete my scan',async()=>{
 const b=await call('POST','/auth/register',{name:'Bob Test',email:'bob@test.dev',password:'Passw0rd!long'});tok.bob=b.data.token;
 const id=(await call('POST','/scans',{url:'https://github.com/login'},tok.alice)).data.scanId;await waitDone(id,tok.alice);
 assert.equal((await call('GET',`/analysis/${id}/report`,null,tok.bob)).status,404);assert.equal((await call('DELETE',`/scans/${id}`,null,tok.bob)).status,404)});
test('reports: create, list, get',async()=>{
 const id=(await call('GET','/scans',null,tok.alice)).data[0].id;const r=await call('POST','/reports',{scanId:id},tok.alice);assert.equal(r.status,201);
 assert.equal((await call('GET','/reports',null,tok.alice)).data.length,1);assert.equal((await call('GET',`/reports/${r.data.id}`,null,tok.alice)).data.scanId,id);
 assert.equal((await call('GET',`/reports/${r.data.id}`,null,tok.bob)).status,404)});
test('RBAC + admin users CRUD',async()=>{
 assert.equal((await call('GET','/admin/users',null,tok.alice)).status,403);
 await mkUser('admin@test.dev','admin');await mkUser('super@test.dev','super_admin');
 tok.admin=(await call('POST','/auth/login',{email:'admin@test.dev',password:'Passw0rd!long'})).data.token;tok.super=(await call('POST','/auth/login',{email:'super@test.dev',password:'Passw0rd!long'})).data.token;
 const users=await call('GET','/admin/users',null,tok.admin);assert.equal(users.status,200);const bob=users.data.find(u=>u.email==='bob@test.dev');
 assert.equal((await call('PATCH',`/admin/users/${bob.id}`,{status:'Suspended'},tok.admin)).data.status,'Suspended');
 assert.equal((await call('GET','/scans',null,tok.bob)).status,403); // suspended account is blocked
 assert.equal((await call('PATCH',`/admin/users/${bob.id}`,{role:'analyst'},tok.admin)).status,403); // only super admin changes roles
 assert.equal((await call('PATCH',`/admin/users/${bob.id}`,{role:'analyst',status:'Active'},tok.super)).data.role,'analyst');
 assert.equal((await call('DELETE',`/admin/users/${bob.id}`,null,tok.admin)).status,403);
 assert.equal((await call('POST','/admin/users',{email:'invitee@test.dev',role:'user'},tok.admin)).status,201);
 assert.equal((await call('DELETE',`/admin/users/${bob.id}`,null,tok.super)).status,200);
 const ov=await call('GET','/admin/overview',null,tok.admin);assert.equal(ov.status,200);assert.ok(ov.data.stats.users>=3)});
test('admin scans + threat blocklist CRUD + lookup',async()=>{
 const all=await call('GET','/admin/scans',null,tok.admin);assert.ok(all.data.length>=1);const sid=all.data[0].id;
 assert.equal((await call('PATCH',`/admin/scans/${sid}/review`,null,tok.admin)).status,200);
 assert.equal((await call('GET','/admin/scans',null,tok.admin)).data.find(s=>s.id===sid).status,'Reviewed');
 const add=await call('POST','/admin/threats',{indicator:'Evil-Test-Domain.com',category:'Credential theft',severity:'High'},tok.admin);assert.equal(add.status,201);assert.equal(add.data.indicator,'evil-test-domain.com');
 assert.equal((await call('POST','/admin/threats',{indicator:'evil-test-domain.com',category:'x1',severity:'High'},tok.admin)).status,409);
 assert.equal((await call('GET','/threat-intelligence/lookup?q=evil-test-domain.com',null,tok.alice)).data.reputation,'Malicious');
 assert.equal((await call('PATCH',`/admin/threats/${add.data.id}`,{status:'Disabled'},tok.admin)).data.status,'Disabled');
 assert.equal((await call('DELETE',`/admin/threats/${add.data.id}`,null,tok.admin)).status,200);
 assert.equal((await call('GET','/admin/threats',null,tok.alice)).status,403)});
test('audit log records activity; non-admins cannot read it',async()=>{
 const l=await call('GET','/audit?limit=100',null,tok.admin);assert.equal(l.status,200);const acts=l.data.map(x=>x.action);
 for(const a of ['REGISTER','LOGIN','LOGIN_FAILED','URL_SCAN','SCAN_DELETE','BLOCKLIST_ADD'])assert.ok(acts.includes(a),a);
 assert.equal((await call('GET','/audit',null,tok.alice)).status,403)});
test('attachments: static analysis stores metadata only',async()=>{
 const fd=new FormData();fd.append('file',new Blob(['MZ-fake'],{type:'application/pdf'}),'invoice_Q3.pdf.exe');
 const r=await fetch(base+'/attachments',{method:'POST',headers:{Authorization:`Bearer ${tok.alice}`},body:fd}),j=await r.json();assert.equal(r.status,201);assert.equal(j.data.mismatch,true);assert.match(j.data.sha256,/^[a-f0-9]{64}$/);
 assert.equal((await db.query('select count(*)::int n from attachment_analyses')).rows[0].n,1)});
