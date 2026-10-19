const {test}=require('node:test'),assert=require('node:assert/strict');
const {createJobQueue}=require('../../src/services/scanJobs');
const tick=ms=>new Promise(r=>setTimeout(r,ms));
test('runs jobs and never exceeds the concurrency limit',async()=>{
 const q=createJobQueue({concurrency:2});let running=0,peak=0,done=0;
 for(let i=0;i<8;i++)q.enqueue(async()=>{running++;peak=Math.max(peak,running);await tick(15);running--;done++});
 assert.ok(q.stats().active<=2);await q.drain();assert.deepEqual([done,peak,q.stats()],[8,2,{active:0,queued:0}]);
});
test('a failing job is reported and does not stop the queue',async()=>{
 const errors=[],q=createJobQueue({concurrency:1,onError:e=>errors.push(e.message)});let ok=0;
 q.enqueue(async()=>{throw new Error('boom')});q.enqueue(()=>{throw new Error('sync boom')});q.enqueue(async()=>{ok++});
 await q.drain();assert.deepEqual([errors,ok],[['boom','sync boom'],1]);
});
test('jobs start in FIFO order',async()=>{const q=createJobQueue({concurrency:1}),order=[];for(const i of [1,2,3,4])q.enqueue(async()=>{order.push(i);await tick(2)});await q.drain();assert.deepEqual(order,[1,2,3,4])});
test('drain resolves immediately when idle, and for jobs added later',async()=>{
 const q=createJobQueue({concurrency:1});await q.drain();let hit=false;q.enqueue(async()=>{await tick(10);hit=true});await q.drain();assert.equal(hit,true);
});
