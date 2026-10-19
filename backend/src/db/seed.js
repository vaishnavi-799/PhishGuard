// Development seed data. Refuses to run in production. Usage: npm run db:seed [-- --force]
const bcrypt=require('bcryptjs'),env=require('../config/env'),db=require('../config/db'),User=require('../models/user'),Scan=require('../models/scan'),Report=require('../models/report'),Audit=require('../models/audit'),Threat=require('../models/threat'),{analyze}=require('../services/mockAnalyzer');
const FEEDS=[['PhishTank','1.4M URLs'],['OpenPhish','320k URLs'],['Google Safe Browsing','4.2B URLs'],['VirusTotal','70+ engines'],['URLhaus','2.1M URLs'],['AbuseIPDB','28M IPs'],['AlienVault OTX','19M pulses'],['Spamhaus','Domain & IP lists']];
const IND=[['paypa1-secure.com','Domain','Credential theft','High','PhishTank'],['185.220.101.4','IP','Malware delivery','High','AbuseIPDB'],['m365-reauth.net','Domain','Credential theft','High','OpenPhish'],['dhl-track-parcel.info/in','URL','Smishing','Medium','Internal ML'],['upi-refund-claim.xyz','Domain','Payment fraud','High','Community'],['bank-secure-alert.top','Domain','Credential theft','High','PhishTank']];
const URLS=['https://secure-paypa1-login.com/verify','https://github.com/login','https://microsoft-365-reauth.net/login','https://docs.google.com/forms','http://bank-secure-alert.top/kyc','https://amazon.in/orders','https://dhl-track-parcel.info/in','https://linkedin.com/jobs','https://upi-refund-claim.xyz/pay','https://bit.ly/3xRz9aQ','https://wikipedia.org/wiki/Phishing','https://netflix-billing.live/update','https://www.example-shop.com/checkout','https://zoom-meeting-invite.co/j/884'];
const EXTRA=[['Priya Nair','priya.nair@phishguard.test','analyst','Active'],['Omar Haddad','omar.haddad@phishguard.test','user','Active'],['Sara Khan','sara.khan@phishguard.test','user','Suspended'],['Tom Brandt','tom.brandt@phishguard.test','user','Pending'],['Mia Rossi','mia.rossi@phishguard.test','user','Inactive']];
(async()=>{try{
 if(env.isProd)throw new Error('Refusing to seed a production database');
 const mk=async(name,email,role,status,pw)=>{const ex=await User.findByEmail(email);return ex||User.create({name,email,role,status,passwordHash:await bcrypt.hash(pw,env.bcryptRounds)})};
 const out=[];
 if(process.env.SEED_ADMIN_EMAIL&&process.env.SEED_ADMIN_PASSWORD){if(process.env.SEED_ADMIN_PASSWORD.length<12)throw new Error('SEED_ADMIN_PASSWORD must be at least 12 characters');out.push(await mk(process.env.SEED_ADMIN_NAME||'Super Admin',process.env.SEED_ADMIN_EMAIL,'super_admin','Active',process.env.SEED_ADMIN_PASSWORD))}
 const demoPw=process.env.SEED_DEMO_PASSWORD;
 if(demoPw){if(demoPw.length<12)throw new Error('SEED_DEMO_PASSWORD must be at least 12 characters');
  for(const [n,e,r,s] of [['Demo Admin','admin.demo@phishguard.test','admin','Active'],['Demo Analyst','analyst.demo@phishguard.test','analyst','Active'],['Demo User','user.demo@phishguard.test','user','Active'],...EXTRA])out.push(await mk(n,e,r,s,demoPw))}
 else console.log('SEED_DEMO_PASSWORD not set: skipping demo users');
 for(const [n,c] of FEEDS)await db.query('insert into threat_feeds(name,coverage) values($1,$2) on conflict (name) do nothing',[n,c]);
 await db.query("update threat_feeds set status='Degraded' where name='AbuseIPDB'");
 for(const [i,t,c,s,src] of IND)await db.query('insert into threat_indicators(indicator,type,category,severity,source) values($1,$2,$3,$4,$5) on conflict (indicator) do nothing',[i,t,c,s,src]);
 const active=out.filter(u=>u.status==='Active');
 const have=(await db.query('select count(*)::int n from scans')).rows[0].n;
 if(active.length&&(!have||process.argv.includes('--force'))){let n=0;const ids=[];
  for(let k=0;k<40;k++){const u=active[k%active.length],base=URLS[k%URLS.length],url=k<URLS.length?base:`${base}${base.includes('?')?'&':'?'}ref=${k}`;
   ids.push([await Scan.createWithAnalysis({userId:u.id,url,analysis:analyze(url),createdAt:new Date(Date.now()-k*9*36e5),status:k%7===3?'Reviewed':'Completed'}),u.id]);n++}
  for(const [sid,uid] of ids.slice(0,12))await Report.create({scanId:sid,userId:uid,sizeKb:90+(sid*37)%310});
  for(const u of active.slice(0,3)){await Audit.insert({userId:u.id,email:u.email,action:'LOGIN',ip:'10.0.0.5',result:'Success',detail:'Seed login'})}
  await Audit.insert({email:'unknown',action:'LOGIN_FAILED',ip:'203.0.113.9',result:'Failure',detail:'Invalid credentials (seed)'});
  console.log(`Seeded ${n} scans with full analysis, 12 reports`)}
 else console.log(have?'Scans already exist: skipping scan seed (use --force to add more)':'No active users to own scans');
 console.log(`Seed complete (${out.length} users ensured)`)}catch(e){console.error('Seed failed:',e.message);process.exitCode=1}finally{await db.pool.end()}})();
