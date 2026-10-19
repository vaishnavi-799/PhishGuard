const {Pool,types}=require('pg'),env=require('./env');
types.setTypeParser(20,v=>parseInt(v,10));types.setTypeParser(1700,v=>parseFloat(v)); // bigint / numeric -> JS number
const pool=new Pool({connectionString:env.databaseUrl,ssl:env.dbSsl?{rejectUnauthorized:false}:false,max:10});
// Run several statements atomically: tx(async client => { await client.query(...) })
async function tx(fn){const c=await pool.connect();try{await c.query('begin');const r=await fn(c);await c.query('commit');return r}catch(e){await c.query('rollback').catch(()=>{});throw e}finally{c.release()}}
module.exports={pool,tx,query:(text,params)=>pool.query(text,params)};
