// Usage: node src/db/migrate.js [up|status|reset --yes]
const fs=require('fs'),path=require('path'),crypto=require('crypto'),db=require('../config/db'),env=require('../config/env');
const DIR=path.join(__dirname,'migrations'),LOCK=727274,sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const files=()=>fs.readdirSync(DIR).filter(f=>/^\d+_.+\.sql$/.test(f)).sort();
async function ensure(c){await c.query(`create table if not exists schema_migrations(version varchar(10) primary key,name text not null,checksum char(64) not null,applied_at timestamptz not null default now())`)}
async function up(){const c=await db.pool.connect();try{await c.query('select pg_advisory_lock($1)',[LOCK]);await ensure(c);
 if((await c.query("select 1 from information_schema.columns where table_schema='public' and table_name='users' and column_name='role'")).rowCount)
  throw new Error('Legacy prototype schema detected (users.role). In development run: npm run db:reset -- --yes');
 const done=new Map((await c.query('select version,checksum from schema_migrations')).rows.map(r=>[r.version,r.checksum]));let n=0;
 for(const f of files()){const[version,...rest]=f.replace('.sql','').split('_'),sql=fs.readFileSync(path.join(DIR,f),'utf8'),sum=sha(sql);
  if(done.has(version)){if(done.get(version)!==sum)throw new Error(`Migration ${f} was modified after it was applied`);continue}
  await c.query('begin');try{await c.query(sql);await c.query('insert into schema_migrations(version,name,checksum) values($1,$2,$3)',[version,rest.join('_'),sum]);await c.query('commit');console.log('Applied',f);n++}
  catch(e){await c.query('rollback');throw new Error(`${f}: ${e.message}`)}}
 console.log(n?`Applied ${n} migration(s).`:'Database is up to date.')}finally{await c.query('select pg_advisory_unlock($1)',[LOCK]).catch(()=>{});c.release()}}
async function status(){await db.query(`create table if not exists schema_migrations(version varchar(10) primary key,name text not null,checksum char(64) not null,applied_at timestamptz not null default now())`);
 const done=new Set((await db.query('select version from schema_migrations')).rows.map(r=>r.version));files().forEach(f=>console.log(done.has(f.split('_')[0])?'[applied]':'[pending]',f))}
async function reset(){if(env.isProd)throw new Error('Refusing to reset a production database');if(!process.argv.includes('--yes'))throw new Error('This DROPS ALL DATA. Re-run with --yes to confirm.');
 await db.query('drop schema public cascade');await db.query('create schema public');console.log('Schema dropped.');await up()}
module.exports={up,status,reset};
if(require.main===module){const cmd=process.argv[2]||'up';({up,status,reset}[cmd]||(()=>Promise.reject(new Error('Unknown command: '+cmd))))().catch(e=>{console.error('Migration error:',e.message);process.exitCode=1}).finally(()=>db.pool.end())}
