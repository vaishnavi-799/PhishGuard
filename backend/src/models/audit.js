const db=require('../config/db'),{pub}=require('../utils/ids'),{fmt}=require('../utils/format');
const COLS='id,user_id,user_email,action,resource_type,resource_id,host(ip) as ip,result,detail,created_at';
const toApi=l=>({id:pub('L',l.id),user:l.user_email||'unknown',action:l.action,ip:l.ip||'—',timestamp:fmt(l.created_at),result:l.result,detail:l.detail||''});
module.exports={toApi,
 insert:({userId,email,action,ip,result,detail,resourceType,resourceId})=>db.query('insert into audit_logs(user_id,user_email,action,resource_type,resource_id,ip,result,detail) values($1,$2,$3,$4,$5,$6,$7,$8)',[userId||null,email||null,action,resourceType||null,resourceId||null,ip||null,result,detail||null]),
 list:async({limit,offset,action,result,q})=>(await db.query(`select ${COLS} from audit_logs where ($1::text is null or action=$1) and ($2::text is null or result=$2) and ($3::text is null or user_email ilike $3 or host(ip) ilike $3) order by created_at desc,id desc limit $4 offset $5`,[action||null,result||null,q?`%${q}%`:null,limit,offset])).rows.map(toApi),
 recentProblems:async n=>(await db.query(`select ${COLS} from audit_logs where result<>'Success' order by created_at desc limit $1`,[n])).rows,
 activeUsersByDay:()=>db.query(`select to_char(d,'Dy') as name,count(distinct a.user_id) as count from generate_series((current_date-6)::timestamp,current_date::timestamp,interval '1 day') d left join audit_logs a on a.created_at::date=d::date and a.user_id is not null and a.result='Success' group by d order by d`).then(r=>r.rows)};
