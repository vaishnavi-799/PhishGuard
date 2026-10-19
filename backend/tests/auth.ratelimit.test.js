// Separate file = separate process, so the limiter can be configured tightly. Run via: npm test
process.env.AUTH_RATE_LIMIT_MAX='3';process.env.REGISTER_RATE_LIMIT_MAX='2';
const assert=require('node:assert/strict'),{test,before,after}=require('node:test'),h=require('./helpers'),{call}=h;
before(h.start);after(h.stop);
test('login limiter blocks after repeated FAILED attempts (429), per IP',async()=>{
 for(let i=0;i<3;i++)assert.equal((await call('POST','/auth/login',{email:`u${i}@test.dev`,password:'WrongPass1'})).status,401);
 const r=await call('POST','/auth/login',{email:'u9@test.dev',password:'WrongPass1'});assert.equal(r.status,429);assert.equal(r.body.error.code,'RATE_LIMITED')});
test('registration limiter blocks mass sign-ups',async()=>{
 for(let i=0;i<2;i++)assert.equal((await call('POST','/auth/register',{name:'Rate User',email:`r${i}@test.dev`,password:'Passw0rd!long'})).status,201);
 assert.equal((await call('POST','/auth/register',{name:'Rate User',email:'r9@test.dev',password:'Passw0rd!long'})).status,429)});
