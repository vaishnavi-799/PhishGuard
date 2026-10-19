const Scan=require('../models/scan'),analysis=require('./analysisService'),analysisService=analysis,env=require('../config/env'),logger=require('../utils/logger'),{createJobQueue}=require('./scanJobs'),ApiError=require('../utils/ApiError'),{can}=require('../config/rbac'),{pub,parse}=require('../utils/ids'),{toApiScan}=require('../utils/format');
const RISK=[['Very Low','#22c55e'],['Low','#84cc16'],['Medium','#f59e0b'],['High','#f97316'],['Critical','#ef4444']];
const RECS=[{id:1,icon:'🔐',title:'Use a strong, unique password',text:'Rotate passwords regularly and never reuse them.',priority:'High'},{id:2,icon:'🚨',title:'Review high-risk scans',text:'Check critical results from the last 24 hours.',priority:'High'},{id:3,icon:'📣',title:'Report confirmed phishing',text:'Forward confirmed phishing to your IT team.',priority:'Medium'},{id:4,icon:'🧩',title:'Update your browser',text:'Latest versions include improved Safe Browsing protection.',priority:'Low'}];
// Loads a scan the caller may access: owner, or staff with scans:read.
exports.getAccessible=async(user,publicId)=>{const id=parse('S',publicId);if(!id)throw new ApiError(404,'Scan not found','NOT_FOUND');
 const row=await Scan.findSummary(id);if(!row||(row.user_id!==user.dbId&&!can(user.role,'scans:read')))throw new ApiError(404,'Scan not found','NOT_FOUND');return row};
const jobs=createJobQueue({concurrency:env.analysis.concurrency,onError:e=>logger.error('scan job crashed',{err:e.message})});
exports.jobs=jobs;
const SAFE={INVALID_URL:'The URL could not be analysed',BUSY:'The analysis service is busy, please retry',UNAVAILABLE:'The analysis service is unavailable',TIMEOUT:'The analysis timed out',UPSTREAM:'The analysis failed',BAD_RESPONSE:'The analysis failed',UNAUTHORIZED:'The analysis service is misconfigured'};
// The background job: analyse, persist, or mark the scan as failed. Never throws, never leaks internal error details to users.
async function runAnalysis(id,url){
 try{const{analysis,report}=await analysisService.analyze(url);await Scan.saveAnalysis(id,analysis,report)}
 catch(e){logger.error('analysis failed',{scan:id,code:e.code,err:e.message});await Scan.markFailed(id,SAFE[e.code]||'The analysis failed').catch(()=>{})}
}
exports.runAnalysis=runAnalysis;
// Returns immediately with the scan id; the client polls /scans/:id/status (the URL was already validated by the request validator).
exports.create=async(user,url)=>{const id=await Scan.createPending({userId:user.dbId,url,host:new URL(url).hostname});jobs.enqueue(()=>runAnalysis(id,url));return{scanId:pub('S',id)}};
exports.status=async(user,publicId)=>{
 const row=await exports.getAccessible(user,publicId);
 if(row.status==='Failed')return{status:'failed',stageIndex:0,progress:0,error:row.error_message||'The analysis failed'};
 if(row.status!=='Running')return{status:'completed',stageIndex:analysis.STAGE_MS.length-1,progress:100};
 const el=Date.now()-new Date(row.created_at).getTime();
 if(el>env.analysis.staleSeconds*1000){await Scan.markFailed(row.id,'The analysis timed out');return{status:'failed',stageIndex:0,progress:0,error:'The analysis timed out'}}
 const D=analysis.STAGE_MS,total=D.reduce((a,b)=>a+b,0);let acc=0,idx=D.length-2; // progress is an estimate: real analysis time varies
 for(let i=0;i<D.length-1;i++){acc+=D[i];if(el<acc){idx=i;break}}
 return{status:'running',stageIndex:idx,progress:Math.min(95,Math.round(el/total*100))};
};
exports.cancel=async(user,publicId)=>{const row=await exports.getAccessible(user,publicId);if(row.user_id!==user.dbId)throw new ApiError(403,'Not your scan','FORBIDDEN');await Scan.remove(row.id)};
exports.remove=exports.cancel;
exports.list=async user=>(await Scan.listByUser(user.dbId)).map(toApiScan);
exports.overview=async(user,uid=user.dbId)=>{const [c,a7,a30,b,recent,ind]=await Promise.all([Scan.counts(uid),Scan.activity(uid,7),Scan.activity(uid,30),Scan.riskBuckets(uid),Scan.listByUser(uid,8),require('../models/threat').top(5)]);
 const num=r=>r.map(x=>({day:x.day,scans:x.scans,threats:x.threats})),bm=Object.fromEntries(b.map(x=>[x.b,x.n]));
 return{stats:{total:c.total,phishing:c.phishing,highCritical:c.high_critical,safe:c.safe},activity7:num(a7),activity30:num(a30),
 riskDist:RISK.map(([name,color],i)=>({name,value:bm[i]||0,color})),detection:[{name:'Phishing',count:c.phishing,color:'#ef4444'},{name:'Legitimate',count:c.total-c.phishing,color:'#22c55e'}],
 recs:RECS,scans:recent.map(toApiScan),indicators:ind.map(t=>({id:t.id,domain:t.indicator,category:t.category,severity:t.severity,source:t.source,seen:new Date(t.created_at).toISOString().slice(0,16).replace('T',' ')}))}};
exports.RISK=RISK;
