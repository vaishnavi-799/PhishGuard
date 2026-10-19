const db=require('../config/db'),{pub}=require('../utils/ids'),{fmt}=require('../utils/format');
const SQL='select r.*,s.target,s.score,s.prediction from reports r join scan_summaries s on s.id=r.scan_id';
const toApi=(r,includeData=false)=>({id:pub('R',r.id),scanId:pub('S',r.scan_id),target:r.target,score:r.score,prediction:r.prediction,generated:fmt(r.created_at),size:`${r.file_size_kb} KB`,...(includeData?{data:r.report_data||null}:{})});
module.exports={toApi,
 create:async({scanId,userId,sizeKb,format='json',reportData})=>{const r=(await db.query('insert into reports(scan_id,user_id,format,file_size_kb,report_data) values($1,$2,$3,$4,$5) returning id',[scanId,userId,format,sizeKb,JSON.stringify(reportData)])).rows[0];return toApi((await db.query(`${SQL} where r.id=$1`,[r.id])).rows[0])},
 updateData:async(id,uid,reportData,sizeKb)=>db.query('update reports set report_data=$3,file_size_kb=$4 where id=$1 and user_id=$2',[id,uid,JSON.stringify(reportData),sizeKb]),
 listByUser:async uid=>(await db.query(`${SQL} where r.user_id=$1 order by r.created_at desc`,[uid])).rows.map(toApi),
 findForUser:async(id,uid)=>{const r=(await db.query(`${SQL} where r.id=$1 and r.user_id=$2`,[id,uid])).rows[0];return r&&toApi(r,true)},
 remove:async(id,uid)=>(await db.query('delete from reports where id=$1 and user_id=$2',[id,uid])).rowCount};
