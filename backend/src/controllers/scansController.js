const svc=require('../services/scanService'),{toApiScan}=require('../utils/format'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.list=h(async(req,res)=>ok(res,await svc.list(req.user)));
exports.overview=h(async(req,res)=>ok(res,await svc.overview(req.user)));
exports.create=h(async(req,res)=>{const r=await svc.create(req.user,req.body.url);await audit.log({req,user:req.user,action:'URL_SCAN',detail:`Submitted ${r.scanId}`});ok(res,r,201)});
exports.status=h(async(req,res)=>ok(res,await svc.status(req.user,req.params.id)));
exports.get=h(async(req,res)=>ok(res,toApiScan(await svc.getAccessible(req.user,req.params.id))));
exports.cancel=h(async(req,res)=>{await svc.cancel(req.user,req.params.id);ok(res,{cancelled:true})});
exports.remove=h(async(req,res)=>{await svc.remove(req.user,req.params.id);await audit.log({req,user:req.user,action:'SCAN_DELETE',detail:req.params.id});ok(res,{deleted:true})});
