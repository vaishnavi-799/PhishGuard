// Shared setup for integration tests. Needs TEST_DATABASE_URL (database name must contain "test"); the schema is WIPED.
const crypto=require('crypto');
const url=process.env.TEST_DATABASE_URL;
if(!url||!/test/i.test(new URL(url).pathname)){console.error('Set TEST_DATABASE_URL to a disposable database whose name contains "test"');process.exit(1)}
const def=(k,v)=>{process.env[k]=process.env[k]||v};
Object.assign(process.env,{DATABASE_URL:url,NODE_ENV:'test',LOG_LEVEL:'error',BCRYPT_ROUNDS:'4',CORS_ORIGIN:'http://localhost:3000'});
def('RATE_LIMIT_MAX','100000');def('AUTH_RATE_LIMIT_MAX','100000');def('REGISTER_RATE_LIMIT_MAX','100000');
process.env.JWT_SECRET=process.env.JWT_SECRET||crypto.randomBytes(32).toString('hex');
const db=require('../src/config/db'),migrate=require('../src/db/migrate'),app=require('../src/app'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
let server,base;
exports.db=db;exports.jwt=jwt;
exports.start=async()=>{await db.query('drop schema public cascade');await db.query('create schema public');await migrate.up();server=app.listen(0);base=`http://127.0.0.1:${server.address().port}/api`};
exports.stop=async()=>{await require('../src/services/scanService').jobs.drain();server&&server.close();await db.pool.end()};
exports.call=async(method,path,body,token,headers={})=>{const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{}),...headers},body:body?JSON.stringify(body):undefined});let j=null;try{j=await r.json()}catch{}return{status:r.status,headers:r.headers,body:j,data:j&&j.data}};
exports.mkUser=async(email,role,pw='Passw0rd!long')=>{await db.query('insert into users(role_id,name,email,password_hash) values((select id from roles where name=$1),$2,$3,$4)',[role,`${role} user`,email,await bcrypt.hash(pw,4)])};
exports.login=async(email,pw='Passw0rd!long')=>(await exports.call('POST','/auth/login',{email,password:pw})).data?.token;
exports.raw=(path,headers={})=>new Promise((res,rej)=>require('http').get(base+path,{headers},r=>{r.resume();res(r)}).on('error',rej)); // node:http lets us set the Origin header
// Scans are analysed in the background: poll until the scan leaves the 'running' state
exports.waitDone=async(id,token,ms=10000)=>{const t=Date.now();for(;;){const s=await exports.call('GET',`/scans/${id}/status`,null,token);if(s.data&&s.data.status!=='running')return s.data;if(Date.now()-t>ms)throw new Error(`scan ${id} still running after ${ms}ms`);await new Promise(r=>setTimeout(r,50))}};
exports.secret=()=>process.env.JWT_SECRET;
