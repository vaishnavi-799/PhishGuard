// Minimal in-process job queue with bounded concurrency. Jobs do NOT survive a restart (interrupted scans are failed on boot).
// For multi-instance deployments replace this with a persistent queue (BullMQ, pg-boss, SQS...).
function createJobQueue({concurrency=4,onError=()=>{}}={}){
 const q=[];let active=0,waiters=[];
 const settle=()=>{if(active===0&&q.length===0){waiters.forEach(w=>w());waiters=[]}};
 function pump(){while(active<concurrency&&q.length){const job=q.shift();active++;Promise.resolve().then(job).catch(onError).finally(()=>{active--;pump();settle()})}}
 return{enqueue(job){q.push(job);pump()},stats:()=>({active,queued:q.length}),drain:()=>new Promise(res=>{if(active===0&&q.length===0)res();else waiters.push(res)})};
}
module.exports={createJobQueue};
