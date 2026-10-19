const db=require('../config/db');
module.exports={insert:({userId,filename,size,sha256,score,result})=>db.query('insert into attachment_analyses(user_id,filename,size_bytes,sha256,risk_score,result) values($1,$2,$3,$4,$5,$6)',[userId,filename,size,/^[a-f0-9]{64}$/.test(sha256)?sha256:'0'.repeat(64),score,JSON.stringify(result)])};
