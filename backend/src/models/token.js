const db=require('../config/db');
module.exports={
 revoke:async({jti,userId,exp})=>{await db.query('insert into revoked_tokens(jti,user_id,expires_at) values($1,$2,to_timestamp($3)) on conflict (jti) do nothing',[jti,userId,exp]);
  await db.query('delete from revoked_tokens where expires_at<now()')}, // housekeeping: expired tokens are rejected by exp anyway
 isRevoked:async jti=>(await db.query('select 1 from revoked_tokens where jti=$1',[jti])).rowCount>0};
