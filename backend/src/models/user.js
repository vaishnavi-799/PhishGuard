const db=require('../config/db'),{pub}=require('../utils/ids'),{fmt,fmtDate}=require('../utils/format');
const SEL='select u.*,r.name as role from users u join roles r on r.id=u.role_id';
const toPublic=u=>({id:pub('U',u.id),name:u.name,email:u.email,role:u.role,status:u.status});
const toAdmin=u=>({...toPublic(u),scans:u.scans||0,created:fmtDate(u.created_at),lastActive:fmt(u.last_active_at)});
const findById=async id=>(await db.query(`${SEL} where u.id=$1`,[id])).rows[0];
module.exports={toPublic,toAdmin,findById,
 findByEmail:async e=>(await db.query(`${SEL} where u.email=$1`,[String(e).toLowerCase()])).rows[0],
 create:async({name,email,passwordHash,role='user',status='Active'},client=db)=>{const r=await client.query('insert into users(role_id,name,email,password_hash,status) values((select id from roles where name=$4),$1,$2,$3,$5) returning id',[name,email.toLowerCase(),passwordHash,role,status]);return findById(r.rows[0].id)},
 updateProfile:async(id,{name})=>{await db.query('update users set name=$2 where id=$1',[id,name]);return findById(id)},
 updatePassword:async(id,hash)=>{await db.query('update users set password_hash=$2,token_version=token_version+1 where id=$1',[id,hash]);return findById(id)}, // bumping token_version signs out every existing session
 markLogin:id=>db.query('update users set last_login_at=now(),last_active_at=now(),failed_login_attempts=0,locked_until=null where id=$1',[id]),
 recordFailedLogin:(id,max,mins)=>db.query('update users set locked_until=case when failed_login_attempts+1>=$2 then now()+make_interval(mins=>$3) else locked_until end,failed_login_attempts=case when failed_login_attempts+1>=$2 then 0 else failed_login_attempts+1 end where id=$1',[id,max,mins]),
 revokeAllSessions:id=>db.query('update users set token_version=token_version+1 where id=$1',[id]),
 touch:id=>db.query("update users set last_active_at=now() where id=$1 and (last_active_at is null or last_active_at<now()-interval '5 minutes')",[id]),
 listAdmin:async()=>(await db.query(`${SEL.replace('select u.*,','select u.*,(select count(*) from scans s where s.user_id=u.id) as scans,')} order by u.id`)).rows.map(toAdmin),
 adminUpdate:async(id,{role,status})=>{await db.query('update users set role_id=coalesce((select id from roles where name=$2),role_id),status=coalesce($3,status) where id=$1',[id,role||null,status||null]);return findById(id)},
 remove:id=>db.query('delete from users where id=$1',[id])};
