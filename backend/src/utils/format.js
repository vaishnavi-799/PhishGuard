const {pub}=require('./ids');
const fmt=d=>d?new Date(d).toISOString().slice(0,16).replace('T',' '):'—';
const fmtDate=d=>d?new Date(d).toISOString().slice(0,10):'—';
const toApiScan=r=>({id:pub('S',r.id),target:r.target,score:r.score,type:r.type,verdict:r.score>=70?'Phishing':r.score>=40?'Suspicious':'Safe',user:r.email,date:fmt(r.created_at),category:r.category,prediction:r.prediction,confidence:r.confidence,status:r.status});
module.exports={fmt,fmtDate,toApiScan};
