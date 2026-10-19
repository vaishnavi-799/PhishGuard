// Authentication & authorization tests. Run: npm test   (see tests/helpers.js)
const assert=require('node:assert/strict'),{test,before,after}=require('node:test'),h=require('./helpers');
const {call,db,mkUser,login}=h,PW='Passw0rd!long',tok={};
before(h.start);after(h.stop);

test('successful registration',async()=>{
 const r=await call('POST','/auth/register',{name:'Alice Test',email:'Alice@Test.dev',password:PW});
 assert.equal(r.status,201);assert.equal(r.body.success,true);assert.ok(r.data.token);assert.equal(r.data.user.email,'alice@test.dev');assert.equal(r.data.user.role,'user');
 assert.equal(r.headers.get('cache-control'),'no-store');
 assert.deepEqual(Object.keys(r.data.user).sort(),['email','id','name','role','status'],'user payload must not expose password data');
 const row=(await db.query("select password_hash from users where email='alice@test.dev'")).rows[0];assert.match(row.password_hash,/^\$2[aby]\$\d{2}\$/);assert.ok(!row.password_hash.includes(PW));
 tok.alice=r.data.token});
test('registration cannot choose a role or send extra fields; weak input is rejected',async()=>{
 assert.equal((await call('POST','/auth/register',{name:'Mallory',email:'m@test.dev',password:PW,role:'admin'})).status,400);
 const weak=await call('POST','/auth/register',{name:'Weak One',email:'weak@test.dev',password:'short'});assert.equal(weak.status,400);assert.equal(weak.body.error.code,'VALIDATION_ERROR');assert.ok(weak.body.error.details.length>0);
 assert.equal((await call('POST','/auth/register',{name:'No Digits',email:'nd@test.dev',password:'onlyletters'})).status,400);
 assert.equal((await call('POST','/auth/register',{name:'Bad Email',email:'not-an-email',password:PW})).status,400);
 assert.equal((await call('POST','/auth/register',{name:'Long Pw',email:'lp@test.dev',password:'a1'+'x'.repeat(80)})).status,400);
 assert.equal((await db.query("select count(*)::int n from users where email in ('m@test.dev','weak@test.dev','nd@test.dev','lp@test.dev')")).rows[0].n,0)});
test('duplicate email is rejected (case-insensitive)',async()=>{
 for(const email of ['alice@test.dev','ALICE@TEST.DEV']){const r=await call('POST','/auth/register',{name:'Alice Two',email,password:PW});assert.equal(r.status,409);assert.equal(r.body.error.code,'EMAIL_TAKEN')}
 assert.equal((await db.query("select count(*)::int n from users where email='alice@test.dev'")).rows[0].n,1)});
test('successful login returns a working token',async()=>{
 const r=await call('POST','/auth/login',{email:'alice@test.dev',password:PW});assert.equal(r.status,200);assert.ok(r.data.token);assert.equal(r.data.user.role,'user');
 const me=await call('GET','/auth/me',null,r.data.token);assert.equal(me.status,200);assert.equal(me.data.user.name,'Alice Test');assert.ok(!('dbId' in me.data.user))});
test('wrong password and unknown email give the same generic 401',async()=>{
 const a=await call('POST','/auth/login',{email:'alice@test.dev',password:'WrongPass1'}),b=await call('POST','/auth/login',{email:'nobody@test.dev',password:'WrongPass1'});
 assert.equal(a.status,401);assert.equal(b.status,401);assert.equal(a.body.error.message,b.body.error.message);assert.equal(a.body.error.code,'INVALID_CREDENTIALS');
 assert.ok(!/stack|at /.test(JSON.stringify(a.body)),'no stack traces in errors')});
test('protected API rejects missing, malformed, forged, tampered and expired tokens',async()=>{
 assert.equal((await call('GET','/scans')).status,401);
 for(const bad of ['garbage','a.b.c','Bearer'])assert.equal((await call('GET','/scans',null,bad)).status,401);
 const id=(await call('GET','/auth/me',null,tok.alice)).data.user.id,sub=String(+id.slice(2)-1000);
 const claims={tv:0},fixed={issuer:'phishguard',audience:'phishguard-web',subject:sub,jwtid:'11111111-1111-4111-8111-111111111111'};
 const forged=h.jwt.sign(claims,'x'.repeat(40),{algorithm:'HS256',expiresIn:'1h',...fixed});assert.equal((await call('GET','/scans',null,forged)).status,401);
 const expired=h.jwt.sign(claims,h.secret(),{algorithm:'HS256',expiresIn:-60,...fixed});assert.equal((await call('GET','/scans',null,expired)).status,401);
 const wrongAud=h.jwt.sign(claims,h.secret(),{algorithm:'HS256',expiresIn:'1h',...fixed,audience:'other'});assert.equal((await call('GET','/scans',null,wrongAud)).status,401);
 const none=Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')+'.'+Buffer.from(JSON.stringify({sub,tv:0,iss:'phishguard',aud:'phishguard-web'})).toString('base64url')+'.';assert.equal((await call('GET','/scans',null,none)).status,401);
 assert.equal((await call('GET','/scans',null,tok.alice)).status,200)});
test('normal user cannot access any admin API (403) and the attempt is audited',async()=>{
 await mkUser('admin@test.dev','admin');tok.admin=await login('admin@test.dev');
 for(const p of ['/admin/overview','/admin/users','/admin/scans','/admin/threats','/audit'])assert.equal((await call('GET',p,null,tok.alice)).status,403,p);
 assert.equal((await call('POST','/admin/threats',{indicator:'x.example.com',category:'Test',severity:'High'},tok.alice)).status,403);
 assert.equal((await call('POST','/admin/users',{email:'inv@test.dev',role:'admin'},tok.alice)).status,403);
 await new Promise(r=>setTimeout(r,300));
 const logs=(await call('GET','/audit?limit=100',null,tok.admin)).data;assert.ok(logs.some(l=>l.action==='ACCESS_DENIED'&&l.result==='Blocked'))});
test('admin can access admin APIs (200)',async()=>{
 for(const p of ['/admin/overview','/admin/users','/admin/scans','/admin/threats','/audit'])assert.equal((await call('GET',p,null,tok.admin)).status,200,p);
 assert.ok((await call('GET','/admin/users',null,tok.admin)).data.some(u=>u.email==='alice@test.dev'))});
test('role comes from the database, not the token: demoting an admin takes effect immediately',async()=>{
 await mkUser('temp.admin@test.dev','admin');const t=await login('temp.admin@test.dev');assert.equal((await call('GET','/admin/users',null,t)).status,200);
 await db.query("update users set role_id=(select id from roles where name='user') where email='temp.admin@test.dev'");assert.equal((await call('GET','/admin/users',null,t)).status,403)});
test('users can use user features but only see their own data',async()=>{
 const s=await call('POST','/scans',{url:'https://secure-paypa1-login.com/verify'},tok.alice);assert.equal(s.status,201);assert.equal((await h.waitDone(s.data.scanId,tok.alice)).status,'completed');
 assert.equal((await call('GET','/scans',null,tok.alice)).data.length,1);assert.equal((await call('GET','/threat-intelligence/lookup?q=example.com',null,tok.alice)).status,200);
 assert.equal((await call('POST','/reports',{scanId:s.data.scanId},tok.alice)).status,201);
 const b=await call('POST','/auth/register',{name:'Bob Test',email:'bob@test.dev',password:PW});assert.equal((await call('GET','/scans',null,b.data.token)).data.length,0);assert.equal((await call('GET',`/analysis/${s.data.scanId}/report`,null,b.data.token)).status,404)});
test('logout revokes the token immediately',async()=>{
 const t=await login('alice@test.dev');assert.equal((await call('GET','/auth/me',null,t)).status,200);
 assert.equal((await call('POST','/auth/logout',null,t)).status,200);assert.equal((await call('GET','/auth/me',null,t)).status,401);assert.equal((await call('POST','/auth/logout',null,t)).status,401);
 assert.equal((await db.query('select count(*)::int n from revoked_tokens')).rows[0].n,1);assert.equal((await call('GET','/auth/me',null,tok.alice)).status,200,'other sessions are unaffected')});
test('logout-all signs out every session',async()=>{const t1=await login('alice@test.dev'),t2=await login('alice@test.dev');assert.equal((await call('POST','/auth/logout-all',null,t1)).status,200);for(const t of [t1,t2,tok.alice])assert.equal((await call('GET','/auth/me',null,t)).status,401);tok.alice=await login('alice@test.dev')});
test('changing the password invalidates old tokens',async()=>{
 const old=tok.alice,r=await call('PUT','/users/me/password',{currentPassword:'WrongPass1',newPassword:'N3wPassword!long'},old);assert.equal(r.status,400);
 const ok=await call('PUT','/users/me/password',{currentPassword:PW,newPassword:'N3wPassword!long'},old);assert.equal(ok.status,200);assert.ok(ok.data.token);
 assert.equal((await call('GET','/auth/me',null,old)).status,401);assert.equal((await call('GET','/auth/me',null,ok.data.token)).status,200);
 assert.equal((await call('POST','/auth/login',{email:'alice@test.dev',password:PW})).status,401);assert.equal((await call('POST','/auth/login',{email:'alice@test.dev',password:'N3wPassword!long'})).status,200)});
test('account locks after 5 failed attempts, even for the right password, then recovers',async()=>{
 await mkUser('lock@test.dev','user');
 for(let i=0;i<5;i++)assert.equal((await call('POST','/auth/login',{email:'lock@test.dev',password:'WrongPass1'})).status,401);
 const locked=await call('POST','/auth/login',{email:'lock@test.dev',password:PW});assert.equal(locked.status,429);assert.equal(locked.body.error.code,'ACCOUNT_LOCKED');
 await db.query("update users set locked_until=now()-interval '1 minute' where email='lock@test.dev'");assert.equal((await call('POST','/auth/login',{email:'lock@test.dev',password:PW})).status,200);
 assert.equal((await db.query("select failed_login_attempts n from users where email='lock@test.dev'")).rows[0].n,0)});
test('suspended accounts cannot log in or use existing tokens',async()=>{
 await mkUser('susp@test.dev','user');const t=await login('susp@test.dev');await db.query("update users set status='Suspended' where email='susp@test.dev'");
 assert.equal((await call('POST','/auth/login',{email:'susp@test.dev',password:PW})).status,403);assert.equal((await call('GET','/scans',null,t)).status,403)});
test('security headers (Helmet), CORS and error hygiene',async()=>{
 const r=await h.raw('/health');assert.equal(r.headers['x-content-type-options'],'nosniff');assert.equal(r.headers['x-powered-by'],undefined);assert.ok(r.headers['x-frame-options']||r.headers['content-security-policy']);
 assert.equal((await h.raw('/health',{Origin:'http://localhost:3000'})).headers['access-control-allow-origin'],'http://localhost:3000');
 assert.equal((await h.raw('/health',{Origin:'https://evil.example'})).headers['access-control-allow-origin'],undefined);
 const nf=await call('GET','/nope');assert.equal(nf.status,404);assert.equal(nf.body.error.code,'NOT_FOUND');
 const j=await call('POST','/auth/login','not-json');assert.ok([400,401].includes(j.status))});
