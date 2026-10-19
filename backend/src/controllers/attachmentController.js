const svc=require('../services/attachmentService'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.analyze=h(async(req,res)=>{const r=await svc.analyze(req.user,req.file);await audit.log({req,user:req.user,action:'FILE_SCAN',detail:`${r.name} (score ${r.score})`});ok(res,r,201)});
