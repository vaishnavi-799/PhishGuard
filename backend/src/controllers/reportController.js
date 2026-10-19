const svc=require('../services/reportService'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.list=h(async(req,res)=>ok(res,await svc.list(req.user)));
exports.create=h(async(req,res)=>{const r=await svc.create(req.user,req.body.scanId);await audit.log({req,user:req.user,action:'REPORT_EXPORT',detail:r.id});ok(res,r,201)});
exports.get=h(async(req,res)=>ok(res,await svc.get(req.user,req.params.id)));
exports.download=h(async(req,res)=>{const d=await svc.download(req.user,req.params.id,req.query.format||'json');await audit.log({req,user:req.user,action:'REPORT_EXPORT',detail:`${req.params.id} ${req.query.format||'json'}`});res.setHeader('Content-Type',d.contentType);res.setHeader('Content-Disposition',`attachment; filename="${d.filename}"`);res.send(d.body)});
