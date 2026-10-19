const env=require('../config/env');const L={error:0,warn:1,info:2,http:3,debug:4};
const log=(lvl,msg,meta)=>{if(L[lvl]>(L[env.logLevel]??2))return;(lvl==='error'?console.error:console.log)(JSON.stringify({time:new Date().toISOString(),level:lvl,msg,...meta}))};
module.exports=Object.fromEntries(Object.keys(L).map(k=>[k,(m,meta)=>log(k,m,meta)]));
