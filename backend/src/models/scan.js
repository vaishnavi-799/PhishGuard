const db=require('../config/db');
const rows=async(sql,p,c=db)=>(await c.query(sql,p)).rows;
const ins=(c,table,o)=>{const k=Object.keys(o);return c.query(`insert into ${table}(${k.join(',')}) values(${k.map((_,i)=>'$'+(i+1)).join(',')})`,k.map(x=>o[x]))}; // table + keys come from code, never from user input
const first=(c,t,id)=>c.query(`select * from ${t} where scan_id=$1`,[id]).then(r=>r.rows[0]||null);
const DONE="status in ('Completed','Reviewed')"; // statistics ignore scans that are still running or failed
// Inserts every analysis part for an existing scan (inside the caller's transaction)
async function insertAnalysis(c,s,a){
 await ins(c,'scan_results',{scan_id:s,...a.scan_result});await ins(c,'url_indicators',{scan_id:s,...a.url_indicators});await ins(c,'domain_indicators',{scan_id:s,...a.domain_indicators});
 await ins(c,'tls_analysis',{scan_id:s,...a.tls_analysis});await ins(c,'website_analysis',{scan_id:s,...a.website_analysis});await ins(c,'risk_assessments',{scan_id:s,...a.risk});
 for(const b of a.brand_matches)await ins(c,'brand_matches',{scan_id:s,...b});
 for(const t of a.threat_results)await ins(c,'threat_intelligence_results',{scan_id:s,...t});
 for(const r of a.recommendations)await ins(c,'recommendations',{scan_id:s,...r});
}
const Scan={
 // Synchronous creation with full analysis (seed data, tests)
 createWithAnalysis:({userId,url,analysis:a,createdAt=new Date(),status='Completed'})=>db.tx(async c=>{
  const s=(await c.query('insert into scans(user_id,target_url,host,status,created_at,completed_at) values($1,$2,$3,$4,$5,$6) returning id',[userId,url,a.host,status,createdAt,new Date(+createdAt+6900)])).rows[0].id;
  await insertAnalysis(c,s,a);return s}),
 // Asynchronous flow: create as Running, analyse in the background, then saveAnalysis / markFailed
 createPending:async({userId,url,host})=>(await db.query("insert into scans(user_id,target_url,host,status) values($1,$2,$3,'Running') returning id",[userId,url,host])).rows[0].id,
 saveAnalysis:(id,a,report)=>db.tx(async c=>{
  const cur=await c.query("select id from scans where id=$1 and status='Running' for update",[id]);
  if(!cur.rowCount)return false; // deleted, cancelled or already failed while the analysis was running
  await insertAnalysis(c,id,a);
  if(report)await c.query('insert into analysis_reports(scan_id,schema_version,engine_version,duration_ms,report) values($1,$2,$3,$4,$5)',[id,String(report.schema_version).slice(0,10),String(report.engine_version||'').slice(0,20),Number.isInteger(report.duration_ms)?report.duration_ms:null,JSON.stringify(report)]);
  await c.query("update scans set status='Completed',completed_at=now(),error_message=null where id=$1",[id]);return true}),
 markFailed:(id,message)=>db.query("update scans set status='Failed',completed_at=now(),error_message=$2 where id=$1 and status='Running'",[id,String(message||'Analysis failed').slice(0,200)]),
 failStale:async seconds=>(await db.query("update scans set status='Failed',completed_at=now(),error_message='Analysis was interrupted or timed out' where status='Running' and created_at<now()-make_interval(secs=>$1)",[seconds])).rowCount,
 loadEngineReport:async id=>(await rows('select report from analysis_reports where scan_id=$1',[id]))[0]?.report||null,
 findSummary:async id=>(await rows('select * from scan_summaries where id=$1',[id]))[0],
 listByUser:(uid,limit=500)=>rows('select * from scan_summaries where user_id=$1 order by created_at desc limit $2',[uid,limit]),
 listAll:(limit=1000)=>rows('select * from scan_summaries order by created_at desc limit $1',[limit]),
 setReviewed:(id,reviewerId)=>db.query("update scans set status='Reviewed',reviewed_by=$2,reviewed_at=now() where id=$1",[id,reviewerId]),
 remove:id=>db.query('delete from scans where id=$1',[id]), // child rows are removed by ON DELETE CASCADE
 loadAnalysis:async id=>{const[url,domain,tls,web,result,risk,brands,intel,recs]=await Promise.all([first(db,'url_indicators',id),first(db,'domain_indicators',id),first(db,'tls_analysis',id),first(db,'website_analysis',id),first(db,'scan_results',id),first(db,'risk_assessments',id),
  rows('select * from brand_matches where scan_id=$1 order by similarity desc',[id]),rows('select * from threat_intelligence_results where scan_id=$1 order by id',[id]),rows('select * from recommendations where scan_id=$1 order by sort_order,id',[id])]);
  return{url,domain,tls,web,result,risk,brands,intel,recs}},
 // uid = null means "all users" (admin)
 counts:async uid=>(await rows(`select count(*) total,count(*) filter(where prediction='Phishing') phishing,count(*) filter(where score>=60) high_critical,count(*) filter(where score<40) safe from scan_summaries where ($1::int is null or user_id=$1) and ${DONE}`,[uid]))[0],
 activity:(uid,days)=>rows(`select to_char(d,'Mon FMDD') as day,count(s.id) as scans,count(s.id) filter(where s.score>=50) as threats from generate_series((current_date-($2::int-1))::timestamp,current_date::timestamp,interval '1 day') d left join scan_summaries s on s.created_at::date=d::date and ($1::int is null or s.user_id=$1) and ${DONE.replace('status','s.status')} group by d order by d`,[uid,days]),
 riskBuckets:uid=>rows(`select case when score<20 then 0 when score<40 then 1 when score<60 then 2 when score<80 then 3 else 4 end as b,count(*) as n from scan_summaries where ($1::int is null or user_id=$1) and ${DONE} group by b`,[uid]),
 categories:()=>rows(`select category as name,count(*) as value from scan_summaries where prediction='Phishing' and ${DONE} group by category order by value desc`)};
module.exports=Scan;
