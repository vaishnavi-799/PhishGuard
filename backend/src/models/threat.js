const db=require('../config/db'),{pub}=require('../utils/ids'),{fmt,fmtDate}=require('../utils/format');
const toApi=t=>({id:pub('T',t.id),indicator:t.indicator,type:t.type,category:t.category,severity:t.severity,source:t.source,status:t.status,added:fmtDate(t.created_at)});
// These rows are a legacy source catalogue. No external-feed adapters are
// configured, so database timestamps/status values must not imply a live sync.
const feedApi=f=>({id:f.id,name:f.name,status:'Offline',enabled:false,feed:f.coverage,updated:'Not configured'});
const one=async(sql,p)=>(await db.query(sql,p)).rows[0];
module.exports={toApi,feedApi,
 list:async()=>(await db.query('select * from threat_indicators order by created_at desc,id desc')).rows.map(toApi),
 add:async({indicator,type,category,severity,source='Manual',status='Active',addedBy})=>toApi(await one('insert into threat_indicators(indicator,type,category,severity,source,status,added_by) values($1,$2,$3,$4,$5,$6,$7) returning *',[indicator,type,category,severity,source,status,addedBy])),
 update:async(id,{status,severity})=>{const r=await one('update threat_indicators set status=coalesce($2,status),severity=coalesce($3,severity) where id=$1 returning *',[id,status||null,severity||null]);return r&&toApi(r)},
 remove:async id=>(await db.query('delete from threat_indicators where id=$1',[id])).rowCount,
 findActive:q=>one("select * from threat_indicators where indicator=$1 and status='Active'",[q.toLowerCase()]),
 top:async n=>(await db.query("select * from threat_indicators where status='Active' order by created_at desc,id desc limit $1",[n])).rows,
 feeds:async()=>(await db.query('select * from threat_feeds order by id')).rows.map(feedApi),
 updateFeed:async(id,{enabled})=>{const r=await one('select id from threat_feeds where id=$1',[id]);return r&&feedApi(r)},
 syncFeed:async id=>{const r=await one('select * from threat_feeds where id=$1',[id]);return r&&feedApi(r)}};
