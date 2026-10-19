const net=require('net'),Audit=require('../models/audit'),logger=require('../utils/logger');
const cleanIp=ip=>{const v=String(ip||'').replace(/^::ffff:/,'');return net.isIP(v)?v:null};
// Never throws: auditing must not break the request. Never pass passwords/tokens in `detail`.
exports.log=async({req,user,email,action,result='Success',detail,resourceType,resourceId})=>{try{await Audit.insert({userId:user?.dbId||null,email:user?.email||email,action,ip:cleanIp(req?.ip),result,detail,resourceType,resourceId})}catch(e){logger.error('audit log failed',{err:e.message})}};
